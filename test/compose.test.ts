import { describe, expect, it } from 'vitest';
import { simpleParser } from 'mailparser';
import { buildRaw, cleanAddresses, envelopeRecipients, forwardDraft, newDraft, replyDraft, COMPOSE_LIMITS } from '../src/compose.js';

const ME = 'me@example.com';

const original = Buffer.from(
  [
    'From: Anna <anna@example.com>',
    'Reply-To: list@example.com',
    'To: me@example.com, bo@example.com',
    'Cc: Cia <cia@example.com>',
    'Subject: Re: Lunch',
    'Date: Mon, 26 Oct 2026 10:00:00 +0000',
    'Message-ID: <m2@example.com>',
    'References: <m1@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b"',
    '',
    '--b',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Noon?',
    '--b',
    'Content-Type: text/plain; name="menu.txt"',
    'Content-Disposition: attachment; filename="menu.txt"',
    '',
    'soup',
    '--b--',
    '',
  ].join('\r\n'),
);

describe('addresses', () => {
  it('accepts plain addresses, lowercases and de-duplicates', () => {
    expect(cleanAddresses([' A@Example.com', 'a@example.com', ''], 'to')).toEqual(['a@example.com']);
  });

  it('rejects display names, lists and header injection', () => {
    expect(() => cleanAddresses(['Anna <a@example.com>'], 'to')).toThrow(/plain email/);
    expect(() => cleanAddresses(['a@example.com, b@example.com'], 'to')).toThrow();
    expect(() => cleanAddresses(['a@example.com\r\nBcc: x@evil.example'], 'to')).toThrow();
  });

  it('enforces the recipient limit across to, cc and bcc', () => {
    const many = Array.from({ length: COMPOSE_LIMITS.recipients + 1 }, (_, i) => `u${i}@example.com`);
    expect(() => envelopeRecipients(newDraft(ME, { to: many, subject: 's', text: 't' }))).toThrow(/at most/);
    expect(() => envelopeRecipients(newDraft(ME, { subject: 's', text: 't' }))).toThrow(/at least one/);
  });
});

describe('replies', () => {
  it('goes to Reply-To, keeps threading headers and does not double "Re:"', async () => {
    const d = await replyDraft(ME, original, { text: 'Yes!' });
    expect(d.to).toEqual(['list@example.com']);
    expect(d.cc).toEqual([]);
    expect(d.subject).toBe('Re: Lunch');
    expect(d.inReplyTo).toBe('<m2@example.com>');
    expect(d.references).toEqual(['<m1@example.com>', '<m2@example.com>']);
    expect(d.text).toMatch(/^Yes!\n\nOn .* wrote:\n> Noon\?/);
  });

  it('reply-all adds the other recipients but never yourself', async () => {
    const d = await replyDraft(ME, original, { text: 'ok', replyAll: true });
    expect(d.to).toEqual(['list@example.com']);
    expect(d.cc.sort()).toEqual(['bo@example.com', 'cia@example.com']);
    expect([...d.to, ...d.cc]).not.toContain(ME);
  });
});

describe('forwards', () => {
  it('prefixes Fwd:, includes the original and its attachments', async () => {
    const d = await forwardDraft(ME, original, { to: ['x@example.com'], text: 'FYI' });
    expect(d.subject).toBe('Fwd: Re: Lunch');
    expect(d.text).toContain('---------- Forwarded message ----------');
    expect(d.text).toContain('Noon?');
    expect(d.attachments?.map(a => a.filename)).toEqual(['menu.txt']);
  });
});

describe('serialization', () => {
  it('keeps Bcc out of the sent headers but in the own copy', async () => {
    const d = newDraft(ME, { to: ['a@example.com'], bcc: ['secret@example.com'], subject: 'Hi\r\nBcc: injected@evil.example', text: 'x' });
    const sent = await simpleParser(await buildRaw(d));
    expect(sent.bcc).toBeUndefined();
    expect(sent.subject).toBe('Hi Bcc: injected@evil.example');
    expect(sent.from?.value[0]?.address).toBe(ME);
    const own = await simpleParser(await buildRaw(d, { keepBcc: true }));
    expect([own.bcc ?? []].flat()[0]?.value[0]?.address).toBe('secret@example.com');
  });
});
