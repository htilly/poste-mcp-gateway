import type { ConnectionOptions } from 'node:tls';
import nodemailer from 'nodemailer';
import { buildRaw, envelopeRecipients, type Draft } from './compose.js';
import type { ImapCredentials } from './imap.js';
import type { MailWriter } from './mail-write.js';
import { silentAudit, type Audit } from './audit.js';

export interface SmtpTarget {
  host: string;
  port: number;
  /** Implicit TLS (465). Otherwise STARTTLS is required (587). */
  secure: boolean;
  servername: string;
  /** Test-only TLS overrides. Never set from config. */
  tls?: ConnectionOptions;
}

export type SendResult =
  | {
      sent: true;
      messageId?: string;
      accepted: string[];
      rejected: string[];
      savedTo?: string;
      saveError?: string;
    }
  | {
      /** Not sent: some recipient was never mailed from this mailbox before. */
      sent: false;
      savedTo: string;
      newRecipients: string[];
      note: string;
    };

/**
 * What to do when a message would go to someone this mailbox has never sent
 * mail to. "draft" (default) saves it to Drafts for the user to review and
 * send themselves; "allow" sends anyway.
 */
export type NewRecipientPolicy = 'draft' | 'allow';

export interface SendPolicy {
  perHour: number;
  newRecipients: NewRecipientPolicy;
  /** Which of these addresses the mailbox has sent to before. */
  previouslySentTo: (creds: ImapCredentials, addresses: string[]) => Promise<Set<string>>;
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
 * same credentials.
 *
 * Mail the assistant reads is untrusted, and a message can carry text meant
 * to make it forward data elsewhere. The server therefore does not rely on
 * the assistant's judgment: mail goes out directly only to addresses this
 * mailbox has sent to before; anything else lands in Drafts for the user.
 * A per-user hourly limit caps the rest.
 */
export class MailSender {
  private readonly sent = new Map<string, number[]>();

  constructor(
    private readonly target: SmtpTarget,
    private readonly writer: MailWriter,
    private readonly policy: SendPolicy,
    private readonly audit: Audit = silentAudit,
    private readonly deliver: Deliver = smtpDeliver,
    private readonly now: () => number = Date.now,
  ) {}

  /** Throws if `user` has used up this hour's sending budget. */
  private reserve(user: string): void {
    const now = this.now();
    const recent = (this.sent.get(user) ?? []).filter(t => now - t < 3600_000);
    if (recent.length >= this.policy.perHour) {
      throw new Error(`sending limit reached (${this.policy.perHour} messages per hour); try again later`);
    }
    recent.push(now);
    this.sent.set(user, recent);
  }

  async send(creds: ImapCredentials, draft: Draft, tool: string): Promise<SendResult> {
    if (draft.from.toLowerCase() !== creds.user.toLowerCase()) throw new Error('can only send as the signed-in mailbox');
    const to = envelopeRecipients(draft);

    if (this.policy.newRecipients === 'draft') {
      const known = await this.policy.previouslySentTo(creds, to);
      const fresh = to.filter(a => !known.has(a));
      if (fresh.length) {
        const { folder } = await this.writer.saveDraft(creds, await buildRaw(draft, { keepBcc: true }));
        this.audit('send_held_as_draft', { user: creds.user, tool, recipients: to, newRecipients: fresh });
        return {
          sent: false,
          savedTo: folder,
          newRecipients: fresh,
          note:
            `Not sent: this mailbox has never sent mail to ${fresh.join(', ')}. ` +
            `The message is saved in ${folder}; the user can review and send it from their mail client.`,
        };
      }
    }

    this.reserve(creds.user);
    const raw = await buildRaw(draft);
    const result = await this.deliver(this.target, creds, { from: creds.user, to }, raw);
    this.audit('mail_sent', { user: creds.user, tool, recipients: to, rejected: result.rejected });
    // Keep a copy in Sent, as mail clients do. Failing to store it does not
    // undo the send, so it is reported rather than thrown.
    try {
      const { folder } = await this.writer.saveSent(creds, await buildRaw(draft, { keepBcc: true }));
      return { sent: true, ...result, savedTo: folder };
    } catch (err) {
      return { sent: true, ...result, saveError: err instanceof Error ? err.message : 'could not store a copy in Sent' };
    }
  }
}
