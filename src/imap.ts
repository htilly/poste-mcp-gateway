import type { ConnectionOptions } from 'node:tls';
import { ImapFlow } from 'imapflow';

export interface ImapTarget {
  host: string;
  port: number;
  servername: string;
  /** Test-only TLS overrides (e.g. a self-signed test server). Never set from config. */
  tls?: ConnectionOptions;
}

export interface ImapCredentials {
  user: string;
  password: string;
}

export function createClient(target: ImapTarget, creds: ImapCredentials): ImapFlow {
  return new ImapFlow({
    host: target.host,
    port: target.port,
    secure: true,
    // Certificate is always verified, against the mail host's real name.
    servername: target.servername,
    tls: { rejectUnauthorized: true, ...target.tls },
    auth: { user: creds.user, pass: creds.password },
    logger: false,
    disableAutoIdle: true,
    connectionTimeout: 15_000,
    greetingTimeout: 10_000,
    socketTimeout: 60_000,
  });
}

export type LoginResult = 'ok' | 'bad_credentials' | 'unavailable';

/**
 * Proves a user owns a mailbox by logging in to it. This is the gateway's
 * whole notion of identity: there are no gateway passwords.
 */
export async function verifyLogin(target: ImapTarget, creds: ImapCredentials): Promise<LoginResult> {
  const client = createClient(target, creds);
  client.on('error', () => {});
  try {
    await client.connect();
    await client.logout();
    return 'ok';
  } catch (err) {
    const e = err as { authenticationFailed?: boolean; responseStatus?: string };
    if (e.authenticationFailed || e.responseStatus === 'NO') return 'bad_credentials';
    return 'unavailable';
  } finally {
    client.close();
  }
}

/**
 * Runs `fn` against one mailbox. By default it is opened read-only (IMAP
 * EXAMINE): the server itself refuses flag changes and expunges, so reading
 * does not depend on this gateway's code alone. All fetches use BODY.PEEK
 * (imapflow's default), so reading never sets \Seen either.
 *
 * `writable` (IMAP SELECT) is for mail-write.ts only, which test/readonly.test.ts
 * enforces; its tools exist only for grants with the mail.modify or mail.send scope.
 */
export async function withMailbox<T>(
  target: ImapTarget,
  creds: ImapCredentials,
  mailbox: string,
  fn: (client: ImapFlow) => Promise<T>,
  { writable = false }: { writable?: boolean } = {},
): Promise<T> {
  return withClient(target, creds, async client => {
    const lock = await client.getMailboxLock(mailbox, { readOnly: !writable });
    try {
      return await fn(client);
    } finally {
      lock.release();
    }
  });
}

/** Connects, runs `fn`, always logs out. One short session per tool call. */
export async function withClient<T>(
  target: ImapTarget,
  creds: ImapCredentials,
  fn: (client: ImapFlow) => Promise<T>,
): Promise<T> {
  const client = createClient(target, creds);
  client.on('error', () => {});
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.logout().catch(() => client.close());
  }
}
