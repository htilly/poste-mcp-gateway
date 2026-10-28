import MailComposer from 'nodemailer/lib/mail-composer/index.js';
import { simpleParser, type AddressObject, type ParsedMail } from 'mailparser';
import { htmlToMarkdown } from './vendor/html-to-markdown.js';

/**
 * Builds outgoing messages: new mail, replies and forwards, as raw RFC 5322
 * bytes for SMTP and for the Drafts/Sent copies. The From address is always
 * the signed-in mailbox; callers cannot choose it.
 */

export const COMPOSE_LIMITS = {
  recipients: 20,
  bodyChars: 100_000,
  quotedChars: 20_000,
  forwardedAttachmentBytes: 10 * 1024 * 1024,
};

export interface Attachment {
  filename?: string;
  content: Buffer;
  contentType: string;
}

export interface Draft {
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text: string;
  inReplyTo?: string;
  references?: string[];
  attachments?: Attachment[];
}

export interface AddressInput {
  to?: string[];
  cc?: string[];
  bcc?: string[];
}

const EMAIL = /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/;

/** Validates and de-duplicates plain addresses (no display names), lowercased. */
export function cleanAddresses(list: string[] | undefined, field: string): string[] {
  const out: string[] = [];
  for (const raw of list ?? []) {
    const addr = raw.trim().toLowerCase();
    if (!addr) continue;
    if (!EMAIL.test(addr)) throw new Error(`${field}: "${raw}" is not a plain email address`);
    if (!out.includes(addr)) out.push(addr);
  }
  return out;
}

function oneLine(s: string): string {
  return s.replace(/[\r\n]+/g, ' ').trim();
}

/** All envelope recipients of a draft, checked against the recipient limit. */
export function envelopeRecipients(d: Draft): string[] {
  const all = [...new Set([...d.to, ...d.cc, ...d.bcc])];
  if (all.length === 0) throw new Error('at least one recipient is required');
  if (all.length > COMPOSE_LIMITS.recipients) {
    throw new Error(`at most ${COMPOSE_LIMITS.recipients} recipients per message`);
  }
  return all;
}

export function newDraft(from: string, input: AddressInput & { subject: string; text: string }): Draft {
  return checkBody({
    from,
    to: cleanAddresses(input.to, 'to'),
    cc: cleanAddresses(input.cc, 'cc'),
    bcc: cleanAddresses(input.bcc, 'bcc'),
    subject: oneLine(input.subject),
    text: input.text,
  });
}

function checkBody(d: Draft): Draft {
  if (d.text.length > COMPOSE_LIMITS.bodyChars) throw new Error(`body is longer than ${COMPOSE_LIMITS.bodyChars} characters`);
  return d;
}

const addressesOf = (field?: AddressObject | AddressObject[]): string[] =>
  [field ?? []].flat().flatMap(a => a.value.map(v => v.address?.toLowerCase()).filter((x): x is string => !!x));

const textOf = (mail: ParsedMail): string =>
  mail.text?.trim() ? mail.text : mail.html ? htmlToMarkdown(mail.html) : '';

function prefixed(prefix: 'Re' | 'Fwd', subject: string | undefined): string {
  const s = oneLine(subject ?? '');
  return new RegExp(`^${prefix}:`, 'i').test(s) ? s : `${prefix}: ${s}`;
}

function quote(mail: ParsedMail): string {
  const body = textOf(mail).slice(0, COMPOSE_LIMITS.quotedChars);
  const who = mail.from?.text ?? 'the sender';
  const when = mail.date ? mail.date.toUTCString() : 'an earlier date';
  return `On ${when}, ${who} wrote:\n` + body.split('\n').map(l => `> ${l}`).join('\n');
}

/**
 * A reply to `original`. Recipients follow mail-client conventions: Reply-To
 * (or From) of the original; with replyAll also its To and Cc, minus yourself.
 */
export async function replyDraft(
  from: string,
  original: Buffer,
  opts: { text: string; replyAll?: boolean; cc?: string[]; bcc?: string[] },
): Promise<Draft> {
  const mail = await simpleParser(original);
  const self = from.toLowerCase();
  const to = addressesOf(mail.replyTo).length ? addressesOf(mail.replyTo) : addressesOf(mail.from);
  const others = opts.replyAll ? [...addressesOf(mail.to), ...addressesOf(mail.cc)] : [];
  const toClean = cleanAddresses(to.filter(a => a !== self), 'to');
  const cc = cleanAddresses([...others, ...(opts.cc ?? [])].filter(a => a !== self && !toClean.includes(a)), 'cc');
  const references = [...[mail.references ?? []].flat(), ...(mail.messageId ? [mail.messageId] : [])];
  return checkBody({
    from,
    to: toClean.length ? toClean : cleanAddresses(to, 'to'),
    cc,
    bcc: cleanAddresses(opts.bcc, 'bcc'),
    subject: prefixed('Re', mail.subject),
    text: `${opts.text}\n\n${quote(mail)}`,
    inReplyTo: mail.messageId,
    references: references.length ? references : undefined,
  });
}

/** A forward of `original`: header block, its text, and its attachments. */
export async function forwardDraft(
  from: string,
  original: Buffer,
  opts: AddressInput & { text: string },
): Promise<Draft> {
  const mail = await simpleParser(original);
  const size = mail.attachments.reduce((n, a) => n + a.size, 0);
  if (size > COMPOSE_LIMITS.forwardedAttachmentBytes) {
    throw new Error(`the original's attachments total ${size} bytes; the forward limit is ${COMPOSE_LIMITS.forwardedAttachmentBytes}`);
  }
  const header = [
    '---------- Forwarded message ----------',
    `From: ${mail.from?.text ?? ''}`,
    `Date: ${mail.date ? mail.date.toUTCString() : ''}`,
    `Subject: ${mail.subject ?? ''}`,
    `To: ${[mail.to ?? []].flat().map(a => a.text).join(', ')}`,
  ].join('\n');
  return checkBody({
    from,
    to: cleanAddresses(opts.to, 'to'),
    cc: cleanAddresses(opts.cc, 'cc'),
    bcc: cleanAddresses(opts.bcc, 'bcc'),
    subject: prefixed('Fwd', mail.subject),
    text: `${opts.text}\n\n${header}\n\n${textOf(mail).slice(0, COMPOSE_LIMITS.quotedChars)}`,
    attachments: mail.attachments.map(a => ({ filename: a.filename, content: a.content, contentType: a.contentType })),
  });
}

/**
 * Serializes a draft. Bcc is left out of the headers, except for the copy
 * kept in the sender's own Sent or Drafts folder (`keepBcc`).
 */
export async function buildRaw(d: Draft, { keepBcc = false }: { keepBcc?: boolean } = {}): Promise<Buffer> {
  const node = new MailComposer({
    from: d.from,
    to: d.to,
    cc: d.cc.length ? d.cc : undefined,
    bcc: d.bcc.length ? d.bcc : undefined,
    subject: d.subject,
    text: d.text,
    inReplyTo: d.inReplyTo,
    references: d.references,
    attachments: d.attachments,
  }).compile();
  node.keepBcc = keepBcc;
  return node.build();
}
