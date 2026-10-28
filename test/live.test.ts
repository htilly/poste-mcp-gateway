/**
 * Runs MailReader and verifyLogin against a real IMAP server: a local
 * GreenMail or Dovecot container (see README, "Live IMAP tests"). Skipped unless
 * LIVE_IMAP=1. Seeds mail with its own imapflow client; that append lives
 * here in test/, never in src/.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { ImapFlow } from 'imapflow';
import { MailReader } from '../src/mail.js';
import { verifyLogin, withMailbox, type ImapTarget } from '../src/imap.js';
import { MailWriter } from '../src/mail-write.js';
import { buildRaw, newDraft } from '../src/compose.js';

const live = process.env.LIVE_IMAP === '1';
const target: ImapTarget = {
  host: '127.0.0.1',
  port: Number(process.env.LIVE_IMAP_PORT ?? 3993),
  servername: 'localhost',
  // GreenMail's self-signed cert names no host; only this test skips verification.
  tls: { rejectUnauthorized: false },
};
// GreenMail: per-user passwords. Dovecot test image: one shared password (LIVE_IMAP_PASSWORD).
const alice = { user: 'alice@example.com', password: process.env.LIVE_IMAP_PASSWORD ?? 'alice-test' };
const bob = { user: 'bob@example.com', password: process.env.LIVE_IMAP_PASSWORD ?? 'bob-test' };
const tag = `t${Date.now()}`;

function rfc822(subject: string, extra: string[] = [], body = 'Hello from the test.'): string {
  return [
    'From: Sender <sender@example.com>',
    'To: alice@example.com',
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    ...extra,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/html; charset=utf-8',
    '',
    `<html><body><p>${body}</p><p style="display:none">preheader</p></body></html>`,
    '--b1',
    'Content-Type: text/plain; name="notes.txt"',
    'Content-Disposition: attachment; filename="notes.txt"',
    '',
    'attachment text',
    '--b1--',
    '',
  ].join('\r\n');
}

describe.skipIf(!live)('live IMAP (GreenMail)', () => {
  const reader = new MailReader(target);

  beforeAll(async () => {
    const client = new ImapFlow({ host: target.host, port: target.port, secure: true, tls: target.tls, auth: { user: alice.user, pass: alice.password }, logger: false });
    await client.connect();
    await client.append('INBOX', rfc822(`${tag} first`, [`Message-ID: <${tag}-1@example.com>`]));
    await client.append('INBOX', rfc822(`Re: ${tag} first`, [`Message-ID: <${tag}-2@example.com>`, `In-Reply-To: <${tag}-1@example.com>`, `References: <${tag}-1@example.com>`]));
    await client.append('INBOX', rfc822('unrelated', [`Message-ID: <${tag}-3@example.com>`]));
    await client.logout();
  });

  it('verifies logins against the server', async () => {
    expect(await verifyLogin(target, alice)).toBe('ok');
    expect(await verifyLogin(target, { ...alice, password: 'nope' })).toBe('bad_credentials');
  });

  it('lists folders', async () => {
    const folders = await reader.listFolders(alice);
    expect(folders.map(f => f.path)).toContain('INBOX');
  });

  it('searches, newest first', async () => {
    const { total, messages } = await reader.search(alice, { folder: 'INBOX', subject: tag });
    expect(total).toBe(2);
    expect(messages[0]!.subject).toBe(`Re: ${tag} first`);
    expect(messages[0]!.uid).toBeGreaterThan(messages[1]!.uid);
  });

  it('free text matches headers but not the body; body search matches the text', async () => {
    expect((await reader.search(alice, { folder: 'INBOX', text: tag })).total).toBe(2);
    expect((await reader.search(alice, { folder: 'INBOX', text: 'sender@example.com', subject: tag })).total).toBe(2);
    expect((await reader.search(alice, { folder: 'INBOX', text: 'Hello from the test', subject: tag })).total).toBe(0);
    expect((await reader.search(alice, { folder: 'INBOX', body: 'Hello from the test', subject: tag })).total).toBe(2);
  });

  it('reads a message without marking it seen', async () => {
    const { messages } = await reader.search(alice, { folder: 'INBOX', subject: `${tag} first` });
    const uid = messages.at(-1)!.uid;
    const msg = await reader.getMessage(alice, 'INBOX', uid);
    expect(msg.body).toContain('Hello from the test.');
    expect(msg.body).not.toContain('preheader');
    expect(msg.attachments).toEqual([{ index: 0, filename: 'notes.txt', contentType: 'text/plain', size: 15 }]);
    const again = await reader.search(alice, { folder: 'INBOX', subject: tag });
    expect(again.messages.every(m => !m.seen)).toBe(true);
  });

  it('reads an attachment', async () => {
    const { messages } = await reader.search(alice, { folder: 'INBOX', subject: tag });
    const att = await reader.getAttachment(alice, 'INBOX', messages[0]!.uid, 0);
    expect(att.content.toString('utf8')).toBe('attachment text');
  });

  it('follows a thread', async () => {
    const { messages } = await reader.search(alice, { folder: 'INBOX', subject: `Re: ${tag}` });
    const thread = await reader.getThread(alice, 'INBOX', messages[0]!.uid);
    expect(thread.map(m => m.subject)).toEqual([`${tag} first`, `Re: ${tag} first`]);
  });

  // GreenMail ignores EXAMINE and accepts STORE; Dovecot (what poste.io runs) refuses it.
  it.skipIf(process.env.LIVE_IMAP_SERVER !== 'dovecot')('opens mailboxes so the server itself refuses changes', async () => {
    const { messages } = await reader.search(alice, { folder: 'INBOX', subject: tag });
    const uid = messages[0]!.uid;
    const changed = await withMailbox(target, alice, 'INBOX', async client => {
      expect(client.mailbox && client.mailbox.readOnly).toBe(true);
      return client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true }).catch(() => false);
    });
    expect(changed).toBe(false);
    const after = await reader.search(alice, { folder: 'INBOX', subject: tag });
    expect(after.messages.every(m => !m.seen)).toBe(true);
  });

  it('keeps users apart', async () => {
    const { total } = await reader.search(bob, { folder: 'INBOX', subject: tag });
    expect(total).toBe(0);
  });

  describe('writes (mail.modify) and sent history (mail.send policy)', () => {
    const writer = new MailWriter(target);
    const seed = async (fn: (c: ImapFlow) => Promise<void>) => {
      const c = new ImapFlow({ host: target.host, port: target.port, secure: true, tls: target.tls, auth: { user: alice.user, pass: alice.password }, logger: false });
      await c.connect();
      try {
        await fn(c);
      } finally {
        await c.logout();
      }
    };

    beforeAll(async () => {
      await seed(async c => {
        for (const f of ['Sent', 'Trash', 'Drafts']) await c.mailboxCreate(f).catch(() => undefined);
        await c.append('Sent', ['From: alice@example.com', `To: anna-${tag}@example.com`, `Subject: sent ${tag}`, '', 'x'].join('\r\n'), ['\\Seen']);
        await c.append('INBOX', ['From: x@evil.example', 'To: alice@example.com', `Subject: write-test ${tag}`, '', 'y'].join('\r\n'));
      });
    });

    it('knows only exact addresses this mailbox has sent to', async () => {
      const known = await reader.previouslySentTo(alice, [`anna-${tag}@example.com`, `nna-${tag}@example.com`, 'x@evil.example']);
      expect([...known]).toEqual([`anna-${tag}@example.com`]);
    });

    it('flags, marks read, moves, trashes and saves drafts', async () => {
      const uid = (await reader.search(alice, { folder: 'INBOX', subject: `write-test ${tag}` })).messages[0]!.uid;
      await writer.setFlagged(alice, 'INBOX', [uid], true);
      await writer.setSeen(alice, 'INBOX', [uid], true);
      const after = (await reader.search(alice, { folder: 'INBOX', subject: `write-test ${tag}` })).messages[0]!;
      expect(after).toMatchObject({ flagged: true, seen: true });

      const folder = `Archive-${tag}`;
      expect(await writer.createFolder(alice, folder)).toMatchObject({ created: true });
      await writer.move(alice, 'INBOX', [uid], folder);
      const moved = (await reader.search(alice, { folder, subject: `write-test ${tag}` })).messages;
      expect(moved).toHaveLength(1);

      expect(await writer.trash(alice, folder, [moved[0]!.uid])).toMatchObject({ to: 'Trash' });
      const trashed = (await reader.search(alice, { folder: 'Trash', subject: `write-test ${tag}` })).messages;
      expect(trashed).toHaveLength(1);
      await expect(writer.trash(alice, 'Trash', [trashed[0]!.uid])).rejects.toThrow(/already in Trash/);

      const draft = newDraft(alice.user, { to: ['someone@example.com'], subject: `draft ${tag}`, text: 'later' });
      expect(await writer.saveDraft(alice, await buildRaw(draft))).toEqual({ folder: 'Drafts' });
      expect((await reader.search(alice, { folder: 'Drafts', subject: `draft ${tag}` })).total).toBe(1);
    });
  });
});
