import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';

/**
 * One user's consent to one OAuth client. Holds the user's IMAP password,
 * sealed; deleting the grant is how access is revoked.
 */
export interface Grant {
  id: string;
  user: string;
  clientId: string;
  sealedPassword: string;
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
  version: 1;
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
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as StateFile;
      if (parsed.version !== 1) throw new Error(`unsupported state version ${parsed.version}`);
      return parsed;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, clients: {}, grants: {} };
      throw err;
    }
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

  /** Drops every grant matching `predicate`. Returns how many went. */
  deleteGrantsWhere(predicate: (grant: Grant) => boolean): number {
    const doomed = Object.values(this.state.grants).filter(predicate);
    for (const grant of doomed) delete this.state.grants[grant.id];
    if (doomed.length) this.save();
    return doomed.length;
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
