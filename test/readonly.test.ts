import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { TOOL_NAMES, registerTools } from '../src/tools.js';
import type { MailReader } from '../src/mail.js';

const SRC = new URL('../src/', import.meta.url).pathname;

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? sources(join(dir, e.name)) : e.name.endsWith('.ts') ? [join(dir, e.name)] : [],
  );
}

// Every imapflow method that can change a mailbox or send anything.
const MUTATING = [
  'messageFlagsAdd', 'messageFlagsRemove', 'messageFlagsSet',
  'messageDelete', 'messageMove', 'messageCopy',
  'append', 'mailboxCreate', 'mailboxDelete', 'mailboxRename',
  'mailboxSubscribe', 'mailboxUnsubscribe', 'setFlagColor', 'setQuota',
];

describe('read-only by construction', () => {
  it('no source file calls a mutating imapflow method', () => {
    const offenders = sources(SRC).flatMap(file => {
      const text = readFileSync(file, 'utf8');
      return MUTATING.filter(m => new RegExp(`\\.${m}\\s*\\(`).test(text)).map(m => `${file}: ${m}`);
    });
    expect(offenders).toEqual([]);
  });

  it('no source file can send mail', () => {
    // Code only: comments may mention SMTP when explaining why it is absent.
    const code = (f: string) => readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '');
    const offenders = sources(SRC).filter(f => /nodemailer|smtp/i.test(code(f)));
    expect(offenders).toEqual([]);
  });

  it('every mailbox is opened read-only', () => {
    const imap = readFileSync(join(SRC, 'imap.ts'), 'utf8');
    const locks = imap.match(/getMailboxLock\([^)]*\)/g) ?? [];
    expect(locks.length).toBeGreaterThan(0);
    for (const call of locks) expect(call).toContain('readOnly: true');
    for (const file of sources(SRC)) {
      if (file.endsWith('imap.ts')) continue;
      expect(readFileSync(file, 'utf8')).not.toMatch(/getMailboxLock|mailboxOpen/);
    }
  });

  it('registers exactly the read tools, all annotated read-only', () => {
    const registered: { name: string; annotations?: Record<string, unknown> }[] = [];
    const fake = {
      registerTool: (name: string, config: { annotations?: Record<string, unknown> }) => {
        registered.push({ name, annotations: config.annotations });
      },
    } as unknown as McpServer;
    registerTools(fake, {
      reader: {} as MailReader,
      credentialsFor: () => ({ grantId: 'g', creds: { user: 'u', password: 'p' } }),
      revokeGrant: () => {},
    });
    expect(registered.map(r => r.name).sort()).toEqual([...TOOL_NAMES].sort());
    for (const r of registered) {
      expect(r.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false });
    }
  });
});
