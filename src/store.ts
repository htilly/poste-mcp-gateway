import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

/** One mailbox in a grant: proven by an IMAP login, its password sealed for that address only. */
export interface GrantAccount {
  user: string;
  sealedPassword: string;
}

/**
 * One person's consent to one OAuth client, covering one or more of their
 * own mailboxes. Holds the sealed IMAP passwords; deleting the grant is how
 * access is revoked.
 */
export interface Grant {
  id: string;
  /** The primary mailbox: the first one signed in, and the default for tools. */
  user: string;
  accounts: GrantAccount[];
  clientId: string;
  scopes: string[];
  resource?: string;
  refreshHash: string;
  /** The refresh token rotated away last; presenting it again revokes the grant. */
  previousRefreshHash?: string;
  refreshExpiresAt: number;
  createdAt: number;
  lastUsedAt: number;
}

interface StateFile {
  version: 2;
  clients: Record<string, OAuthClientInformationFull>;
  grants: Record<string, Grant>;
}

/** Dynamic client registration is unauthenticated, so the client table is capped. */
export const MAX_CLIENTS = 200;
/** Registered clients that never got a grant are dropped after this long. */
const UNUSED_CLIENT_TTL_SEC = 3600;

/**
 * Durable state: registered clients and grants, in one JSON file written
 * atomically (temp file + rename). Sized for a family, not a fleet.
 */
export class Store {
  private state: StateFile;

  constructor(private readonly path: string) {
    this.state = Store.load(path);
  }

  private static load(path: string): StateFile {
    try {
      return Store.migrate(JSON.parse(readFileSync(path, 'utf8')));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { version: 2, clients: {}, grants: {} };
      throw err;
    }
  }

  /** Version 1 grants held a single mailbox (user + sealedPassword); version 2 holds a list. */
  private static migrate(raw: { version: number; clients: StateFile['clients']; grants: Record<string, Record<string, unknown>> }): StateFile {
    if (raw.version === 2) return raw as unknown as StateFile;
    if (raw.version !== 1) throw new Error(`unsupported state version ${raw.version}`);
    const grants: Record<string, Grant> = {};
    for (const [id, g] of Object.entries(raw.grants)) {
      const { sealedPassword, ...rest } = g as unknown as Grant & { sealedPassword: string };
      grants[id] = { ...rest, accounts: [{ user: rest.user, sealedPassword }] };
    }
    return { version: 2, clients: raw.clients, grants };
  }

  private save(): void {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  getClient(id: string): OAuthClientInformationFull | undefined {
    return this.state.clients[id];
  }

  /**
   * Registers a client. When the table is full, the oldest client without a
   * grant makes room, so a flood of registrations cannot lock out real ones;
   * clients that hold grants are never evicted.
   */
  addClient(client: OAuthClientInformationFull): void {
    this.pruneClients();
    if (Object.keys(this.state.clients).length >= MAX_CLIENTS) {
      const inUse = this.clientsInUse();
      const oldest = Object.values(this.state.clients)
        .filter(c => !inUse.has(c.client_id))
        .sort((a, b) => (a.client_id_issued_at ?? 0) - (b.client_id_issued_at ?? 0))[0];
      if (!oldest) throw new Error('client registration limit reached');
      delete this.state.clients[oldest.client_id];
    }
    this.state.clients[client.client_id] = client;
    this.save();
  }

  private clientsInUse(): Set<string> {
    return new Set(Object.values(this.state.grants).map(g => g.clientId));
  }

  private pruneClients(): void {
    const now = Math.floor(Date.now() / 1000);
    const inUse = this.clientsInUse();
    for (const [id, client] of Object.entries(this.state.clients)) {
      const age = now - (client.client_id_issued_at ?? now);
      if (!inUse.has(id) && age > UNUSED_CLIENT_TTL_SEC) delete this.state.clients[id];
    }
  }

  getGrant(id: string): Grant | undefined {
    return this.state.grants[id];
  }

  findGrantByRefreshHash(hash: string): Grant | undefined {
    return Object.values(this.state.grants).find(g => g.refreshHash === hash);
  }

  findGrantByPreviousRefreshHash(hash: string): Grant | undefined {
    return Object.values(this.state.grants).find(g => g.previousRefreshHash === hash);
  }

  putGrant(grant: Grant): void {
    this.state.grants[grant.id] = grant;
    this.save();
  }

  deleteGrant(id: string): boolean {
    if (!this.state.grants[id]) return false;
    delete this.state.grants[id];
    this.save();
    return true;
  }

  listGrants(): Grant[] {
    return Object.values(this.state.grants);
  }

  /**
   * Removes mailboxes that are no longer allowed from every grant. A grant
   * whose primary mailbox is removed is deleted outright, since it was that
   * sign-in that created it.
   */
  pruneAccounts(allowed: (user: string) => boolean): { accounts: number; grants: number } {
    let accounts = 0;
    let grants = 0;
    for (const grant of Object.values(this.state.grants)) {
      if (!allowed(grant.user)) {
        delete this.state.grants[grant.id];
        grants++;
        continue;
      }
      const kept = grant.accounts.filter(a => allowed(a.user));
      accounts += grant.accounts.length - kept.length;
      grant.accounts = kept;
    }
    if (accounts || grants) this.save();
    return { accounts, grants };
  }

  /** Drops grants whose refresh token has expired. Returns how many went. */
  pruneExpiredGrants(now = Date.now()): number {
    let removed = 0;
    for (const grant of Object.values(this.state.grants)) {
      if (grant.refreshExpiresAt <= now) {
        delete this.state.grants[grant.id];
        removed++;
      }
    }
    if (removed) this.save();
    return removed;
  }
}
