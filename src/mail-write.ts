import type { ImapFlow } from 'imapflow';
import { withClient, withMailbox, type ImapCredentials, type ImapTarget } from './imap.js';

/**
 * Every change the gateway can make inside a mailbox. This file and smtp.ts
 * are the only places that may call mutating imapflow methods
 * (test/readonly.test.ts enforces it), and their tools are only registered
 * for grants with the mail.modify or mail.send scope.
 *
 * Deliberately missing: permanent deletion (expunge), and deleting or
 * renaming folders. "Delete" means move to Trash.
 */

/** Upper bound on UIDs per call, so one tool call cannot sweep a whole folder. */
export const MAX_UIDS = 100;

type SpecialUse = '\\Trash' | '\\Drafts' | '\\Sent';
const FALLBACK_NAMES: Record<SpecialUse, string[]> = {
  '\\Trash': ['Trash', 'Deleted Messages', 'Deleted Items'],
  '\\Drafts': ['Drafts'],
  '\\Sent': ['Sent', 'Sent Messages', 'Sent Items'],
};

function checkUids(uids: number[]): string {
  if (uids.length === 0) throw new Error('no UIDs given');
  if (uids.length > MAX_UIDS) throw new Error(`at most ${MAX_UIDS} messages per call`);
  if (!uids.every(u => Number.isInteger(u) && u > 0)) throw new Error('UIDs must be positive integers');
  return uids.join(',');
}

/** Finds a special-use folder (RFC 6154), falling back to common names. */
async function findSpecial(client: ImapFlow, use: SpecialUse): Promise<string> {
  const folders = await client.list();
  const byUse = folders.find(f => f.specialUse === use);
  if (byUse) return byUse.path;
  const lower = new Map(folders.map(f => [f.path.toLowerCase(), f.path]));
  for (const name of FALLBACK_NAMES[use]) {
    const hit = lower.get(name.toLowerCase());
    if (hit) return hit;
  }
  throw new Error(`no ${use.slice(1)} folder found in this mailbox`);
}

export class MailWriter {
  constructor(private readonly target: ImapTarget) {}

  async setSeen(creds: ImapCredentials, folder: string, uids: number[], seen: boolean): Promise<void> {
    await this.setFlag(creds, folder, uids, '\\Seen', seen);
  }

  async setFlagged(creds: ImapCredentials, folder: string, uids: number[], flagged: boolean): Promise<void> {
    await this.setFlag(creds, folder, uids, '\\Flagged', flagged);
  }

  private async setFlag(creds: ImapCredentials, folder: string, uids: number[], flag: string, on: boolean): Promise<void> {
    const range = checkUids(uids);
    await withMailbox(
      this.target,
      creds,
      folder,
      async client => {
        const ok = on
          ? await client.messageFlagsAdd(range, [flag], { uid: true })
          : await client.messageFlagsRemove(range, [flag], { uid: true });
        if (!ok) throw new Error(`the server did not change ${flag}`);
      },
      { writable: true },
    );
  }

  async move(creds: ImapCredentials, folder: string, uids: number[], to: string): Promise<{ moved: number; to: string }> {
    const range = checkUids(uids);
    if (to === folder) throw new Error('source and destination folder are the same');
    return withMailbox(
      this.target,
      creds,
      folder,
      async client => {
        const exists = (await client.list()).some(f => f.path === to);
        if (!exists) throw new Error(`no folder "${to}"; create it first with create_folder`);
        const result = await client.messageMove(range, to, { uid: true });
        if (!result) throw new Error('the server refused the move');
        return { moved: result.uidMap?.size ?? uids.length, to };
      },
      { writable: true },
    );
  }

  /** Moves messages to the Trash folder. Never expunges. */
  async trash(creds: ImapCredentials, folder: string, uids: number[]): Promise<{ moved: number; to: string }> {
    const trash = await withClient(this.target, creds, client => findSpecial(client, '\\Trash'));
    if (trash === folder) {
      throw new Error('these messages are already in Trash; permanent deletion is not supported');
    }
    return this.move(creds, folder, uids, trash);
  }

  async createFolder(creds: ImapCredentials, path: string): Promise<{ path: string; created: boolean }> {
    const clean = path.trim();
    if (!clean) throw new Error('folder path is empty');
    return withClient(this.target, creds, async client => {
      const result = await client.mailboxCreate(clean);
      return { path: result.path, created: result.created };
    });
  }

  /** Stores a composed message in Drafts, flagged \Draft. */
  async saveDraft(creds: ImapCredentials, raw: Buffer): Promise<{ folder: string }> {
    return this.appendTo(creds, '\\Drafts', raw, ['\\Draft', '\\Seen']);
  }

  /** Stores a copy of a sent message in Sent, as mail clients do. */
  async saveSent(creds: ImapCredentials, raw: Buffer): Promise<{ folder: string }> {
    return this.appendTo(creds, '\\Sent', raw, ['\\Seen']);
  }

  private async appendTo(creds: ImapCredentials, use: SpecialUse, raw: Buffer, flags: string[]): Promise<{ folder: string }> {
    return withClient(this.target, creds, async client => {
      const folder = await findSpecial(client, use);
      const result = await client.append(folder, raw, flags);
      if (!result) throw new Error(`the server refused to store the message in ${folder}`);
      return { folder };
    });
  }
}
