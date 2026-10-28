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
  smtpHost: string;
  smtpPort: number;
  /** Implicit TLS (port 465). Otherwise STARTTLS is required. */
  smtpSecure: boolean;
  /** Addresses that may hold mail.send. Empty by default: sending is opt-in per address. */
  sendUsers: Set<string>;
  sendLimitPerHour: number;
  /** "draft" (default): mail to never-before-mailed recipients goes to Drafts. "allow": send anyway. */
  sendNewRecipients: 'draft' | 'allow';
  /** Hosts an OAuth client may redirect to (https). Loopback http is always allowed for desktop clients. */
  allowedRedirectHosts: Set<string>;
  maxGrantAgeSec: number;
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

function parseNewRecipientPolicy(raw: string | undefined): 'draft' | 'allow' {
  const v = (raw ?? 'draft').trim().toLowerCase();
  if (v !== 'draft' && v !== 'allow') throw new Error('SEND_NEW_RECIPIENTS must be "draft" or "allow"');
  return v;
}

export function parseHosts(raw: string): Set<string> {
  return new Set(raw.split(',').map(h => h.trim().toLowerCase()).filter(Boolean));
}

/**
 * Whether an OAuth client may register this redirect URI: https to an
 * allowed host (or a subdomain of one), or http to a loopback address
 * (RFC 8252, desktop clients such as Claude Code).
 */
export function isAllowedRedirectUri(uri: string, hosts: Set<string>): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (url.protocol === 'http:') return host === '127.0.0.1' || host === '[::1]' || host === 'localhost';
  if (url.protocol !== 'https:') return false;
  return [...hosts].some(h => host === h || host.endsWith(`.${h}`));
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const keyFile = env.VAULT_KEY_FILE?.trim();
  const vaultKey = parseVaultKey(keyFile ? readFileSync(keyFile, 'utf8') : required(env, 'VAULT_KEY'));

  const publicUrl = new URL(required(env, 'PUBLIC_URL'));
  const imapHost = required(env, 'IMAP_HOST');
  const allowedUsers = parseAllowedUsers(required(env, 'ALLOWED_USERS'));
  const sendUsers = env.SEND_USERS?.trim() ? parseAllowedUsers(env.SEND_USERS) : new Set<string>();
  for (const user of sendUsers) {
    if (!allowedUsers.has(user)) throw new Error(`SEND_USERS lists ${user}, which is not in ALLOWED_USERS`);
  }
  const smtpPort = Number(env.SMTP_PORT ?? 587);

  return {
    publicUrl,
    listenHost: env.LISTEN_HOST?.trim() || '0.0.0.0',
    listenPort: Number(env.LISTEN_PORT ?? 8080),
    imapHost,
    imapPort: Number(env.IMAP_PORT ?? 993),
    imapServername: env.IMAP_SERVERNAME?.trim() || imapHost,
    allowedUsers,
    vaultKey,
    stateFile: env.STATE_FILE?.trim() || '/state/gateway.json',
    smtpHost: env.SMTP_HOST?.trim() || imapHost,
    smtpPort,
    smtpSecure: env.SMTP_SECURE ? env.SMTP_SECURE === 'true' : smtpPort === 465,
    sendUsers,
    sendLimitPerHour: Number(env.SEND_LIMIT_PER_HOUR ?? 10),
    sendNewRecipients: parseNewRecipientPolicy(env.SEND_NEW_RECIPIENTS),
    allowedRedirectHosts: parseHosts(env.ALLOWED_REDIRECT_HOSTS ?? 'claude.ai,claude.com'),
    maxGrantAgeSec: Number(env.MAX_GRANT_AGE_DAYS ?? 90) * 24 * 3600,
    accessTokenTtlSec: Number(env.ACCESS_TOKEN_TTL ?? 3600),
    refreshTokenTtlSec: Number(env.REFRESH_TOKEN_TTL ?? 30 * 24 * 3600),
  };
}
