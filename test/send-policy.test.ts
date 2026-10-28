import { describe, expect, it } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MailSender, type Deliver } from '../src/smtp.js';
import { newDraft } from '../src/compose.js';
import type { MailWriter } from '../src/mail-write.js';
import { MAX_CLIENTS, Store } from '../src/store.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

const creds = { user: 'me@example.com', password: 'pw' };
const target = { host: 'mail.example.com', port: 587, secure: false, servername: 'mail.example.com' };

function setup(known: string[], { perHour = 10, newRecipients = 'draft' as const } = {}) {
  const delivered: string[][] = [];
  const drafts: number[] = [];
  const events: string[] = [];
  const deliver: Deliver = async (_t, _c, envelope) => {
    delivered.push(envelope.to);
    return { accepted: envelope.to, rejected: [] };
  };
  const writer = {
    saveDraft: async () => (drafts.push(1), { folder: 'Drafts' }),
    saveSent: async () => ({ folder: 'Sent' }),
  } as unknown as MailWriter;
  const sender = new MailSender(
    target,
    writer,
    { perHour, newRecipients, previouslySentTo: async (_c, addrs) => new Set(addrs.filter(a => known.includes(a))) },
    event => events.push(event),
    deliver,
  );
  return { sender, delivered, drafts, events };
}

const draftTo = (...to: string[]) => newDraft(creds.user, { to, subject: 'Hi', text: 'Hello' });

describe('send policy', () => {
  it('sends directly to addresses this mailbox has mailed before', async () => {
    const { sender, delivered, events } = setup(['anna@example.com']);
    const result = await sender.send(creds, draftTo('anna@example.com'), 'send_message');
    expect(result).toMatchObject({ sent: true, savedTo: 'Sent' });
    expect(delivered).toEqual([['anna@example.com']]);
    expect(events).toEqual(['mail_sent']);
  });

  it('holds the whole message as a draft if any recipient is new', async () => {
    const { sender, delivered, drafts, events } = setup(['anna@example.com']);
    const result = await sender.send(creds, draftTo('anna@example.com', 'x@evil.example'), 'forward_message');
    expect(result).toMatchObject({ sent: false, savedTo: 'Drafts', newRecipients: ['x@evil.example'] });
    expect(delivered).toEqual([]);
    expect(drafts).toHaveLength(1);
    expect(events).toEqual(['send_held_as_draft']);
  });

  it('sends to new recipients only when the policy is "allow"', async () => {
    const { sender, delivered } = setup([], { newRecipients: 'allow' as never });
    expect(await sender.send(creds, draftTo('new@example.com'), 'send_message')).toMatchObject({ sent: true });
    expect(delivered).toHaveLength(1);
  });

  it('enforces the hourly limit', async () => {
    const { sender } = setup(['anna@example.com'], { perHour: 2 });
    await sender.send(creds, draftTo('anna@example.com'), 'send_message');
    await sender.send(creds, draftTo('anna@example.com'), 'send_message');
    await expect(sender.send(creds, draftTo('anna@example.com'), 'send_message')).rejects.toThrow(/limit/);
  });

  it('refuses to send as another address', async () => {
    const { sender } = setup(['anna@example.com']);
    const forged = newDraft('boss@example.com', { to: ['anna@example.com'], subject: 's', text: 't' });
    await expect(sender.send(creds, forged, 'send_message')).rejects.toThrow(/signed-in mailbox/);
  });
});

describe('client table', () => {
  it('evicts the oldest unused client when full instead of refusing, and never one with a grant', () => {
    const store = new Store(join(mkdtempSync(join(tmpdir(), 'gw-cl-')), 'state.json'));
    const now = Math.floor(Date.now() / 1000);
    const client = (id: string, at: number) =>
      ({ client_id: id, client_id_issued_at: at, redirect_uris: ['https://claude.ai/cb'] }) as unknown as OAuthClientInformationFull;
    store.addClient(client('in-use', now - 10));
    store.putGrant({
      id: 'g', user: 'me@example.com', accounts: [{ user: 'me@example.com', sealedPassword: 's' }], clientId: 'in-use', scopes: ['mail.read'],
      refreshHash: 'h', refreshExpiresAt: Date.now() + 1000, createdAt: 0, lastUsedAt: 0,
    });
    for (let i = 1; i < MAX_CLIENTS; i++) store.addClient(client(`c${i}`, now - 5 + i / 1000));
    store.addClient(client('newcomer', now));
    expect(store.getClient('newcomer')).toBeDefined();
    expect(store.getClient('in-use')).toBeDefined();
    expect(store.getClient('c1')).toBeUndefined();
  });
});
