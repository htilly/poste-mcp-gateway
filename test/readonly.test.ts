import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { CONNECTION_TOOLS, READ_TOOLS, registerTools } from '../src/tools.js';
import { MODIFY_TOOLS, SEND_TOOLS } from '../src/write-tools.js';
import { SCOPES, type Scope } from '../src/scopes.js';
import type { MailReader } from '../src/mail.js';
import type { MailWriter } from '../src/mail-write.js';
import type { MailSender } from '../src/smtp.js';

const SRC = new URL('../src/', import.meta.url).pathname;

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? sources(join(dir, e.name)) : e.name.endsWith('.ts') ? [join(dir, e.name)] : [],
  );
}

/** Source text without comments: comments may name what the code avoids. */
const code = (file: string) => readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '');

// Every imapflow method that can change a mailbox.
const MUTATING = [
  'messageFlagsAdd', 'messageFlagsRemove', 'messageFlagsSet',
  'messageDelete', 'messageMove', 'messageCopy',
  'append', 'mailboxCreate', 'mailboxDelete', 'mailboxRename',
  'mailboxSubscribe', 'mailboxUnsubscribe', 'setFlagColor', 'setQuota',
];

describe('writes are confined', () => {
  it('only mail-write.ts calls mutating imapflow methods', () => {
    const offenders = sources(SRC)
      .filter(f => basename(f) !== 'mail-write.ts')
      .flatMap(f => MUTATING.filter(m => new RegExp(`\\.${m}\\s*\\(`).test(code(f))).map(m => `${basename(f)}: ${m}`));
    expect(offenders).toEqual([]);
  });

  it('mail-write.ts never expunges or deletes folders', () => {
    const text = code(join(SRC, 'mail-write.ts'));
    for (const m of ['messageDelete', 'mailboxDelete', 'mailboxRename', 'expunge']) {
      expect(text).not.toMatch(new RegExp(`\\.${m}\\s*\\(`));
    }
  });

  it('only smtp.ts can send mail', () => {
    const offenders = sources(SRC)
      .filter(f => basename(f) !== 'smtp.ts')
      .filter(f => /from 'nodemailer'|createTransport|sendMail/.test(code(f)));
    expect(offenders).toEqual([]);
  });

  it('mailboxes open read-only unless mail-write.ts asks otherwise', () => {
    const imap = code(join(SRC, 'imap.ts'));
    expect(imap).toMatch(/writable = false/);
    expect(imap).toMatch(/getMailboxLock\(mailbox, \{ readOnly: !writable \}\)/);
    const writers = sources(SRC).filter(f => /writable: true/.test(code(f))).map(f => basename(f));
    expect(writers).toEqual(['mail-write.ts']);
    for (const file of sources(SRC)) {
      if (basename(file) === 'imap.ts') continue;
      expect(code(file)).not.toMatch(/getMailboxLock|mailboxOpen/);
    }
  });
});

function registered(scopes: Scope[]) {
  const tools: { name: string; annotations?: Record<string, unknown>; params: string[] }[] = [];
  const fake = {
    registerTool: (name: string, config: { annotations?: Record<string, unknown>; inputSchema?: Record<string, unknown> }) => {
      tools.push({ name, annotations: config.annotations, params: Object.keys(config.inputSchema ?? {}) });
    },
  } as unknown as McpServer;
  registerTools(fake, {
    reader: {} as MailReader,
    writer: {} as MailWriter,
    sender: {} as MailSender,
    scopes,
    credentialsFor: () => ({ grantId: 'g', creds: { user: 'u', password: 'p' } }),
    accountsFor: () => ['u'],
    canSend: () => true,
    createAddMailboxLink: () => ({ url: 'https://example.com/add-mailbox?t=x', expiresAt: '' }),
    removeMailbox: () => ['u'],
    revokeGrant: () => {},
  });
  return tools;
}

describe('tools follow the grant\'s scopes', () => {
  it('read only: exactly the read tools, all annotated read-only', () => {
    const tools = registered([SCOPES.read]);
    expect(tools.map(t => t.name).sort()).toEqual([...READ_TOOLS, ...CONNECTION_TOOLS].sort());
    for (const t of tools.filter(t => (READ_TOOLS as readonly string[]).includes(t.name))) {
      expect(t.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
    }
  });

  it('modify adds the modify tools and nothing that sends', () => {
    const names = registered([SCOPES.read, SCOPES.modify]).map(t => t.name).sort();
    expect(names).toEqual([...READ_TOOLS, ...CONNECTION_TOOLS, ...MODIFY_TOOLS].sort());
  });

  it('send adds the send tools, marked destructive and open-world', () => {
    const tools = registered([SCOPES.read, SCOPES.send]);
    expect(tools.map(t => t.name).sort()).toEqual([...READ_TOOLS, ...CONNECTION_TOOLS, ...SEND_TOOLS].sort());
    for (const t of tools.filter(t => (SEND_TOOLS as readonly string[]).includes(t.name))) {
      expect(t.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    }
  });

  it('every mailbox tool takes an optional account; list_accounts does not need one', () => {
    for (const t of registered([SCOPES.read, SCOPES.modify, SCOPES.send])) {
      if (['list_accounts', 'add_mailbox'].includes(t.name)) expect(t.params).toEqual([]);
      else if (t.name === 'remove_mailbox') expect(t.params).toEqual(['address']);
      else expect(t.params).toContain('account');
    }
  });

  it('every non-read tool says it is not read-only', () => {
    const tools = registered([SCOPES.read, SCOPES.modify, SCOPES.send]);
    for (const t of tools.filter(t => !(READ_TOOLS as readonly string[]).includes(t.name))) {
      expect(t.annotations?.readOnlyHint).toBe(false);
    }
  });
});
