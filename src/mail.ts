import type { FetchMessageObject, ImapFlow, SearchObject } from 'imapflow';
import { simpleParser, type ParsedMail } from 'mailparser';
import { htmlToMarkdown } from './vendor/html-to-markdown.js';
import { withClient, withMailbox, type ImapCredentials, type ImapTarget } from './imap.js';

/**
 * Every read the gateway can do, and nothing else. There is deliberately no
 * write method here; imapflow's mutating calls (messageFlagsAdd, messageMove,
 * messageDelete, append, mailboxCreate, ...) are not used anywhere in src/,
 * which test/readonly.test.ts asserts.
 */

export const LIMITS = {
  searchResults: 50,
  bodyChars: 20_000,
  attachmentTextChars: 50_000,
  attachmentBytes: 5 * 1024 * 1024,
};

export interface FolderInfo {
  path: string;
  specialUse?: string;
  messages?: number;
  unseen?: number;
}

export interface MessageSummary {
  uid: number;
  date?: string;
  from?: string;
  to?: string;
  subject?: string;
  seen: boolean;
  flagged: boolean;
  size?: number;
}

export interface AttachmentInfo {
  index: number;
  filename?: string;
  contentType: string;
  size: number;
}

export interface MessageView extends MessageSummary {
  folder: string;
  cc?: string;
  replyTo?: string;
  messageId?: string;
  inReplyTo?: string;
  body: string;
  bodyTruncated: boolean;
  attachments: AttachmentInfo[];
}

export interface SearchQuery {
  folder: string;
  text?: string;
  from?: string;
  to?: string;
  subject?: string;
  since?: string;
  before?: string;
  unseen?: boolean;
  limit?: number;
}

const addr = (list?: { address?: string; name?: string }[]) =>
  list?.map(a => (a.name ? `${a.name} <${a.address}>` : a.address)).join(', ') || undefined;

function summarize(msg: FetchMessageObject): MessageSummary {
  const flags = msg.flags ?? new Set<string>();
  return {
    uid: msg.uid,
    date: msg.envelope?.date ? new Date(msg.envelope.date).toISOString() : undefined,
    from: addr(msg.envelope?.from),
    to: addr(msg.envelope?.to),
    subject: msg.envelope?.subject,
    seen: flags.has('\\Seen'),
    flagged: flags.has('\\Flagged'),
    size: msg.size,
  };
}

function parseDate(value: string | undefined, field: string): Date | undefined {
  if (!value) return undefined;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) throw new Error(`${field} must be a date like 2026-01-31`);
  return d;
}

export function buildSearch(q: SearchQuery): SearchObject {
  const search: SearchObject = {};
  if (q.text) search.text = q.text;
  if (q.from) search.from = q.from;
  if (q.to) search.to = q.to;
  if (q.subject) search.subject = q.subject;
  const since = parseDate(q.since, 'since');
  const before = parseDate(q.before, 'before');
  if (since) search.since = since;
  if (before) search.before = before;
  if (q.unseen) search.seen = false;
  if (Object.keys(search).length === 0) search.all = true;
  return search;
}

function bodyOf(parsed: ParsedMail): string {
  if (parsed.text && parsed.text.trim()) return parsed.text;
  if (parsed.html) return htmlToMarkdown(parsed.html);
  return '';
}

export class MailReader {
  constructor(private readonly target: ImapTarget) {}

  async listFolders(creds: ImapCredentials): Promise<FolderInfo[]> {
    return withClient(this.target, creds, async client => {
      const list = await client.list({ statusQuery: { messages: true, unseen: true } });
      return list
        .filter(f => !f.flags?.has('\\Noselect'))
        .map(f => ({ path: f.path, specialUse: f.specialUse, messages: f.status?.messages, unseen: f.status?.unseen }));
    });
  }

  async search(creds: ImapCredentials, q: SearchQuery): Promise<{ total: number; messages: MessageSummary[] }> {
    const limit = Math.min(Math.max(q.limit ?? 20, 1), LIMITS.searchResults);
    return withMailbox(this.target, creds, q.folder, async client => {
      const uids = (await client.search(buildSearch(q), { uid: true })) || [];
      // Newest first: highest UIDs are the most recently delivered.
      const picked = [...uids].sort((a, b) => b - a).slice(0, limit);
      const messages = picked.length ? await this.summaries(client, picked) : [];
      return { total: uids.length, messages };
    });
  }

  private async summaries(client: ImapFlow, uids: number[]): Promise<MessageSummary[]> {
    const out: MessageSummary[] = [];
    for await (const msg of client.fetch(uids, { uid: true, envelope: true, flags: true, size: true }, { uid: true })) {
      out.push(summarize(msg));
    }
    return out.sort((a, b) => b.uid - a.uid);
  }

  async getMessage(creds: ImapCredentials, folder: string, uid: number): Promise<MessageView> {
    return withMailbox(this.target, creds, folder, async client => {
      const msg = await client.fetchOne(String(uid), { uid: true, envelope: true, flags: true, size: true, source: true }, { uid: true });
      if (!msg || !msg.source) throw new Error(`no message with UID ${uid} in ${folder}`);
      const parsed = await simpleParser(msg.source);
      const body = bodyOf(parsed);
      return {
        ...summarize(msg),
        folder,
        cc: parsed.cc ? [parsed.cc].flat().map(a => a.text).join(', ') : undefined,
        replyTo: parsed.replyTo?.text,
        messageId: parsed.messageId,
        inReplyTo: parsed.inReplyTo,
        body: body.slice(0, LIMITS.bodyChars),
        bodyTruncated: body.length > LIMITS.bodyChars,
        attachments: parsed.attachments.map((a, index) => ({
          index,
          filename: a.filename,
          contentType: a.contentType,
          size: a.size,
        })),
      };
    });
  }

  async getAttachment(
    creds: ImapCredentials,
    folder: string,
    uid: number,
    index: number,
  ): Promise<{ filename?: string; contentType: string; size: number; content: Buffer }> {
    return withMailbox(this.target, creds, folder, async client => {
      const msg = await client.fetchOne(String(uid), { uid: true, source: true }, { uid: true });
      if (!msg || !msg.source) throw new Error(`no message with UID ${uid} in ${folder}`);
      const parsed = await simpleParser(msg.source);
      const att = parsed.attachments[index];
      if (!att) throw new Error(`message ${uid} has no attachment #${index}`);
      if (att.size > LIMITS.attachmentBytes) {
        throw new Error(`attachment is ${att.size} bytes; the limit is ${LIMITS.attachmentBytes}`);
      }
      return { filename: att.filename, contentType: att.contentType, size: att.size, content: att.content };
    });
  }

  /**
   * Messages in a folder that belong to the same conversation as `uid`,
   * matched on Message-ID / In-Reply-To / References headers.
   */
  async getThread(creds: ImapCredentials, folder: string, uid: number): Promise<MessageSummary[]> {
    return withMailbox(this.target, creds, folder, async client => {
      const root = await client.fetchOne(String(uid), { uid: true, headers: ['message-id', 'in-reply-to', 'references'] }, { uid: true });
      if (!root || !root.headers) throw new Error(`no message with UID ${uid} in ${folder}`);
      const ids = new Set(root.headers.toString('utf8').match(/<[^<>\s]+>/g) ?? []);
      if (ids.size === 0) return this.summaries(client, [uid]);
      const found = new Set<number>([uid]);
      for (const id of [...ids].slice(0, 20)) {
        for (const header of ['message-id', 'in-reply-to', 'references']) {
          const hits = (await client.search({ header: { [header]: id } }, { uid: true })) || [];
          hits.forEach(h => found.add(h));
        }
      }
      // Oldest first; same-second Date headers are common, so UID breaks ties.
      return (await this.summaries(client, [...found].slice(0, LIMITS.searchResults))).sort(
        (a, b) => (a.date ?? '').localeCompare(b.date ?? '') || a.uid - b.uid,
      );
    });
  }
}
