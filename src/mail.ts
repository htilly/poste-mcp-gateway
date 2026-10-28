import type { FetchMessageObject, ImapFlow, SearchObject } from 'imapflow';
import { simpleParser, type ParsedMail } from 'mailparser';
import { htmlToMarkdown } from './vendor/html-to-markdown.js';
import { withClient, withMailbox, type ImapCredentials, type ImapTarget } from './imap.js';

/**
 * Every read the gateway can do, and nothing else. All mailboxes are opened
 * read-only (EXAMINE). Changes live in mail-write.ts and sending in smtp.ts;
 * test/readonly.test.ts asserts no other file calls a mutating imapflow method.
 */

export const LIMITS = {
  searchResults: 50,
  bodyChars: 20_000,
  attachmentTextChars: 50_000,
  attachmentBytes: 5 * 1024 * 1024,
  rawSourceBytes: 25 * 1024 * 1024,
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

/** Sender-written header values are capped so one message cannot flood a result. */
const clip = (s: string | undefined, max: number) => (s && s.length > max ? `${s.slice(0, max)}…` : s);

/**
 * Fetches a message's source only after its size is known to be within
 * bounds. Parsing happens fully in memory, so an oversized inbound message
 * must be refused before it is downloaded, not after.
 */
async function fetchBoundedSource(client: ImapFlow, uid: number, folder: string, extra: { envelope?: boolean; flags?: boolean } = {}) {
  const head = await client.fetchOne(String(uid), { uid: true, size: true }, { uid: true });
  if (!head) throw new Error(`no message with UID ${uid} in ${folder}`);
  if ((head.size ?? 0) > LIMITS.rawSourceBytes) {
    throw new Error(`message is ${head.size} bytes; this gateway reads messages up to ${LIMITS.rawSourceBytes} bytes`);
  }
  const msg = await client.fetchOne(String(uid), { uid: true, size: true, source: true, ...extra }, { uid: true });
  if (!msg || !msg.source) throw new Error(`no message with UID ${uid} in ${folder}`);
  return msg;
}

function summarize(msg: FetchMessageObject): MessageSummary {
  const flags = msg.flags ?? new Set<string>();
  return {
    uid: msg.uid,
    date: msg.envelope?.date ? new Date(msg.envelope.date).toISOString() : undefined,
    from: clip(addr(msg.envelope?.from), 500),
    to: clip(addr(msg.envelope?.to), 1000),
    subject: clip(msg.envelope?.subject, 300),
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
      const msg = await fetchBoundedSource(client, uid, folder, { envelope: true, flags: true });
      const parsed = await simpleParser(msg.source!);
      const body = bodyOf(parsed);
      return {
        ...summarize(msg),
        folder,
        cc: clip(parsed.cc ? [parsed.cc].flat().map(a => a.text).join(', ') : undefined, 1000),
        replyTo: clip(parsed.replyTo?.text, 500),
        messageId: parsed.messageId,
        inReplyTo: parsed.inReplyTo,
        body: body.slice(0, LIMITS.bodyChars),
        bodyTruncated: body.length > LIMITS.bodyChars,
        attachments: parsed.attachments.map((a, index) => ({
          index,
          filename: clip(a.filename, 200),
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
      const msg = await fetchBoundedSource(client, uid, folder);
      const parsed = await simpleParser(msg.source!);
      const att = parsed.attachments[index];
      if (!att) throw new Error(`message ${uid} has no attachment #${index}`);
      if (att.size > LIMITS.attachmentBytes) {
        throw new Error(`attachment is ${att.size} bytes; the limit is ${LIMITS.attachmentBytes}`);
      }
      return { filename: att.filename, contentType: att.contentType, size: att.size, content: att.content };
    });
  }

  /**
   * Which of `addresses` this mailbox has sent mail to before (To, Cc or Bcc
   * of a message in Sent). IMAP SEARCH matches substrings, so hits are
   * confirmed against the exact envelope addresses.
   *
   * "Has mailed me" would be useless here: a prompt-injection email arrives
   * from exactly the address it wants data sent to. Sent history is under
   * the user's control.
   */
  async previouslySentTo(creds: ImapCredentials, addresses: string[]): Promise<Set<string>> {
    const wanted = [...new Set(addresses.map(a => a.toLowerCase()))];
    const known = new Set<string>();
    if (wanted.length === 0) return known;
    const sent = await withClient(this.target, creds, async client => {
      const folders = await client.list();
      return (
        folders.find(f => f.specialUse === '\\Sent') ??
        folders.find(f => ['sent', 'sent messages', 'sent items'].includes(f.path.toLowerCase()))
      )?.path;
    });
    if (!sent) return known;
    return withMailbox(this.target, creds, sent, async client => {
      for (const addr of wanted) {
        const hits = new Set<number>();
        for (const field of ['to', 'cc', 'bcc'] as const) {
          for (const uid of (await client.search({ [field]: addr }, { uid: true })) || []) hits.add(uid);
        }
        const recent = [...hits].sort((a, b) => b - a).slice(0, 20);
        if (recent.length === 0) continue;
        for await (const msg of client.fetch(recent, { uid: true, envelope: true }, { uid: true })) {
          const env = msg.envelope;
          const all = [...(env?.to ?? []), ...(env?.cc ?? []), ...(env?.bcc ?? [])];
          if (all.some(a => a.address?.toLowerCase() === addr)) {
            known.add(addr);
            break;
          }
        }
      }
      return known;
    });
  }

  /** The raw RFC 5322 source of one message, for replying to or forwarding it. */
  async getRawSource(creds: ImapCredentials, folder: string, uid: number): Promise<Buffer> {
    return withMailbox(this.target, creds, folder, async client => {
      return (await fetchBoundedSource(client, uid, folder)).source!;
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
