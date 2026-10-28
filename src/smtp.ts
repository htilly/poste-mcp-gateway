import type { ConnectionOptions } from 'node:tls';
import nodemailer from 'nodemailer';
import { buildRaw, envelopeRecipients, type Draft } from './compose.js';
import type { ImapCredentials } from './imap.js';
import type { MailWriter } from './mail-write.js';

export interface SmtpTarget {
  host: string;
  port: number;
  /** Implicit TLS (465). Otherwise STARTTLS is required (587). */
  secure: boolean;
  servername: string;
  /** Test-only TLS overrides. Never set from config. */
  tls?: ConnectionOptions;
}

export interface SendResult {
  messageId?: string;
  accepted: string[];
  rejected: string[];
  savedTo?: string;
  saveError?: string;
}

/** Hands one raw message to the mail server. Injectable for tests. */
export type Deliver = (
  target: SmtpTarget,
  creds: ImapCredentials,
  envelope: { from: string; to: string[] },
  raw: Buffer,
) => Promise<{ messageId?: string; accepted: string[]; rejected: string[] }>;

export const smtpDeliver: Deliver = async (target, creds, envelope, raw) => {
  const transport = nodemailer.createTransport({
    host: target.host,
    port: target.port,
    secure: target.secure,
    requireTLS: !target.secure,
    auth: { user: creds.user, pass: creds.password },
    tls: { servername: target.servername, rejectUnauthorized: true, ...target.tls },
    connectionTimeout: 15_000,
    greetingTimeout: 10_000,
    socketTimeout: 60_000,
  });
  try {
    const info = await transport.sendMail({ envelope, raw });
    const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : []);
    return { messageId: info.messageId, accepted: list(info.accepted), rejected: list(info.rejected) };
  } finally {
    transport.close();
  }
};

/**
 * Sends mail as the signed-in user, through the same mail server, with the
 * same credentials. Limits how much one grant can send, so a prompt-injected
 * request cannot turn the mailbox into a spam cannon.
 */
export class MailSender {
  private readonly sent = new Map<string, number[]>();

  constructor(
    private readonly target: SmtpTarget,
    private readonly writer: MailWriter,
    private readonly perHour: number,
    private readonly deliver: Deliver = smtpDeliver,
    private readonly now: () => number = Date.now,
  ) {}

  /** Throws if `user` has used up this hour's sending budget. */
  private reserve(user: string): void {
    const now = this.now();
    const recent = (this.sent.get(user) ?? []).filter(t => now - t < 3600_000);
    if (recent.length >= this.perHour) {
      throw new Error(`sending limit reached (${this.perHour} messages per hour); try again later`);
    }
    recent.push(now);
    this.sent.set(user, recent);
  }

  async send(creds: ImapCredentials, draft: Draft): Promise<SendResult> {
    if (draft.from.toLowerCase() !== creds.user.toLowerCase()) throw new Error('can only send as the signed-in mailbox');
    const to = envelopeRecipients(draft);
    this.reserve(creds.user);
    const raw = await buildRaw(draft);
    const result = await this.deliver(this.target, creds, { from: creds.user, to }, raw);
    // Keep a copy in Sent, as mail clients do. Failing to store it does not
    // undo the send, so it is reported rather than thrown.
    try {
      const { folder } = await this.writer.saveSent(creds, await buildRaw(draft, { keepBcc: true }));
      return { ...result, savedTo: folder };
    } catch (err) {
      return { ...result, saveError: err instanceof Error ? err.message : 'could not store a copy in Sent' };
    }
  }
}
