import { readFileSync } from 'node:fs';

export interface Config {
  /** External URL the gateway is reached at, e.g. https://mail.example.com:8443. Used as OAuth issuer. */
  publicUrl: URL;
  listenHost: string;
  listenPort: number;
  imapHost: string;
  imapPort: number;
  /**
   * Hostname the IMAP TLS certificate is checked against. Defaults to imapHost.
   * Only differs when imapHost is an IP pinned around a broken local resolver.
   */
  imapServername: string;
  /** Lowercased mailbox addresses allowed to sign in. Anything else is rejected before IMAP is touched. */
  allowedUsers: Set<string>;
  /** 32-byte key sealing stored IMAP passwords. */
  vaultKey: Buffer;
  stateFile: string;
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

/** Reads a 32-byte key given as base64 or hex, from a file (preferred) or the env. */
export function parseVaultKey(raw: string): Buffer {
  const text = raw.trim();
  const key = /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, 'hex') : Buffer.from(text, 'base64');
  if (key.length !== 32) throw new Error('vault key must be 32 bytes (64 hex chars or base64)');
  return key;
}

export function parseAllowedUsers(raw: string): Set<string> {
  const users = raw
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
  if (users.length === 0) throw new Error('ALLOWED_USERS must list at least one address');
  return new Set(users);
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const keyFile = env.VAULT_KEY_FILE?.trim();
  const vaultKey = parseVaultKey(keyFile ? readFileSync(keyFile, 'utf8') : required(env, 'VAULT_KEY'));

  const publicUrl = new URL(required(env, 'PUBLIC_URL'));
  const imapHost = required(env, 'IMAP_HOST');

  return {
    publicUrl,
    listenHost: env.LISTEN_HOST?.trim() || '0.0.0.0',
    listenPort: Number(env.LISTEN_PORT ?? 8080),
    imapHost,
    imapPort: Number(env.IMAP_PORT ?? 993),
    imapServername: env.IMAP_SERVERNAME?.trim() || imapHost,
    allowedUsers: parseAllowedUsers(required(env, 'ALLOWED_USERS')),
    vaultKey,
    stateFile: env.STATE_FILE?.trim() || '/state/gateway.json',
    accessTokenTtlSec: Number(env.ACCESS_TOKEN_TTL ?? 3600),
    refreshTokenTtlSec: Number(env.REFRESH_TOKEN_TTL ?? 30 * 24 * 3600),
  };
}
