import { randomUUID } from 'node:crypto';
import type { Response } from 'express';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import {
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidTargetError,
  InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { Vault, hashToken, newToken } from './crypto.js';
import type { Grant, GrantAccount, Store } from './store.js';
import { LoginGuard } from './login-guard.js';
import type { ImapCredentials, LoginResult } from './imap.js';
import { pageCsp, renderLoginPage } from './login-page.js';
import { SCOPES, type Scope } from './scopes.js';
import { silentAudit, type Audit } from './audit.js';

const PENDING_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
/** How long a finished sign-in answers a duplicate submit with the same redirect. */
const REPLAY_TTL_MS = 60 * 1000;
/** Mailboxes one connection can hold. The sign-in page offers three rows; add_mailbox links can add the rest. */
export const MAX_ACCOUNTS_PER_GRANT = 5;
/** How long an add_mailbox link stays valid. */
const ADD_LINK_TTL_MS = 10 * 60 * 1000;

export interface Login {
  user: string;
  password: string;
}

/** One answer for every refused sign-in, so the page reveals neither the allowlist nor lock state. */
const SIGN_IN_FAILED =
  'Sign-in failed. Check the address and password. After several failed attempts, sign-in pauses for 15 minutes.';

interface PendingAuthorization {
  clientId: string;
  params: AuthorizationParams;
  expiresAt: number;
  /** Set while its IMAP check runs, so the same form cannot be raced in parallel. */
  busy?: boolean;
}

interface AuthCode {
  clientId: string;
  /** Primary mailbox. */
  user: string;
  accounts: GrantAccount[];
  scopes: Scope[];
  params: AuthorizationParams;
  expiresAt: number;
}

/**
 * A one-time link that adds a mailbox to an existing connection. The link
 * only identifies the connection; the mailbox still has to be proven by its
 * own password, entered on the gateway's page, never in the chat.
 */
interface AddLink {
  grantId: string;
  expiresAt: number;
  busy?: boolean;
}

export type AddMailboxOutcome =
  | { kind: 'added'; account: string; accounts: string[] }
  | { kind: 'retry'; status: number; message: string }
  | { kind: 'expired' };

/** A sign-in that already succeeded, kept briefly so a double submit is harmless. */
interface CompletedSignIn {
  user: string;
  location: string;
  expiresAt: number;
}

interface AccessEntry {
  grantId: string;
  clientId: string;
  scopes: string[];
  resource?: string;
  expiresAt: number;
}

export interface ProviderOptions {
  store: Store;
  vault: Vault;
  guard: LoginGuard;
  /** The MCP endpoint URL; the only acceptable RFC 8707 resource. */
  resourceUrl: URL;
  verifyLogin: (creds: ImapCredentials) => Promise<LoginResult>;
  /** Whether this (normalized) address may currently hold mail.send. Re-checked on every token. */
  canSend: (user: string) => boolean;
  /**
   * Whether a client redirect URI may be registered. Dynamic registration is
   * unauthenticated, so this is what stops a stranger's "client" from
   * collecting authorization codes through the genuine sign-in page.
   */
  allowRedirectUri: (uri: string) => boolean;
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
  /** Absolute grant lifetime; refreshing never extends a grant past this. */
  maxGrantAgeSec: number;
  audit?: Audit;
  now?: () => number;
}

export type LoginOutcome =
  | { kind: 'redirect'; location: string }
  | {
      kind: 'retry';
      status: number;
      message: string;
      pendingId: string;
      client: OAuthClientInformationFull;
      params: AuthorizationParams;
      /** Re-check the boxes the user had ticked. */
      requested: Scope[];
    }
  | { kind: 'expired' };

/** The vault AAD for a user's password: a ciphertext only opens for the user it was sealed for. */
const passwordAad = (user: string) => `imap-password:${user}`;

/**
 * OAuth 2.1 authorization server whose only login method is the user's own
 * IMAP credentials. The SDK's mcpAuthRouter handles metadata, registration,
 * PKCE and request validation; this class owns identity and token state.
 *
 * Durable: clients and grants (Store). In memory: pending sign-ins, auth codes
 * and access tokens, all short-lived. A restart only costs clients one refresh.
 */
export class GatewayProvider implements OAuthServerProvider {
  private readonly pending = new Map<string, PendingAuthorization>();
  private readonly codes = new Map<string, AuthCode>();
  private readonly completed = new Map<string, CompletedSignIn>();
  private readonly addLinks = new Map<string, AddLink>();
  private readonly access = new Map<string, AccessEntry>();
  private readonly now: () => number;
  private readonly audit: Audit;

  constructor(private readonly opts: ProviderOptions) {
    this.now = opts.now ?? Date.now;
    this.audit = opts.audit ?? silentAudit;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    const { store, allowRedirectUri } = this.opts;
    return {
      getClient: id => store.getClient(id),
      registerClient: client => {
        const full = client as OAuthClientInformationFull;
        const refused = full.redirect_uris.filter(uri => !allowRedirectUri(String(uri)));
        if (refused.length) {
          this.audit('client_refused', { redirectUris: refused.map(String) });
          throw new InvalidClientMetadataError('redirect_uri not allowed on this server');
        }
        store.addClient(full);
        this.audit('client_registered', { clientId: full.client_id, clientName: full.client_name });
        return full;
      },
    };
  }

  /**
   * The scopes a grant may use right now: what was granted at sign-in,
   * narrowed by current policy (an address removed from SEND_USERS loses
   * mail.send on its next request, not when it next signs in).
   */
  private effectiveScopes(grant: Grant): Scope[] {
    const anyCanSend = grant.accounts.some(a => this.opts.canSend(a.user));
    return grant.scopes.filter(s => s !== SCOPES.send || anyCanSend) as Scope[];
  }

  /**
   * RFC 8707 resource indicators naming this server. Claude sends the MCP
   * endpoint URL; ChatGPT may send the server's origin. Anything else names
   * a different server and is refused.
   */
  private isOurResource(resource: URL): boolean {
    const ours = this.opts.resourceUrl;
    const href = resource.href.replace(/\/$/, '');
    return href === ours.href.replace(/\/$/, '') || href === ours.origin;
  }

  /** Whether this mailbox may send right now. Send tools check it per call. */
  canSend(user: string): boolean {
    return this.opts.canSend(LoginGuard.normalize(user));
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (params.resource && !this.isOurResource(params.resource)) {
      const url = new URL(params.redirectUri);
      url.searchParams.set('error', new InvalidTargetError('').errorCode);
      url.searchParams.set('error_description', 'unknown resource');
      if (params.state) url.searchParams.set('state', params.state);
      res.redirect(url.href);
      return;
    }
    this.sweep();
    const pendingId = newToken();
    this.pending.set(pendingId, { clientId: client.client_id, params, expiresAt: this.now() + PENDING_TTL_MS });
    sendLoginPage(res, 200, { pendingId, client, params });
  }

  /**
   * Handles the sign-in form: one or more mailboxes, the first being the
   * primary. Order matters: the guard runs before any IMAP traffic, its
   * verdict for unknown addresses is indistinguishable from a wrong
   * password, and mailboxes are verified one at a time so every attempt
   * stays reserved and bounded. Any failure fails the whole sign-in.
   */
  async completeLogin(
    pendingId: string,
    rawLogins: Login[],
    ip: string,
    requested: Scope[] = [],
  ): Promise<LoginOutcome> {
    const logins: Login[] = [];
    for (const l of rawLogins) {
      const user = LoginGuard.normalize(l.user);
      if (!user && !l.password) continue;
      if (!logins.some(x => x.user === user)) logins.push({ user, password: l.password });
    }
    const primary = logins[0]?.user ?? '';

    // A second submit of a form that already signed in (double click, Enter
    // plus click) gets the same redirect instead of "expired": the browser
    // usually abandoned the first response, and with it the code.
    const done = this.completed.get(pendingId);
    if (done && done.expiresAt > this.now() && done.user === primary) {
      return { kind: 'redirect', location: done.location };
    }

    const pending = this.pending.get(pendingId);
    if (!pending || pending.expiresAt <= this.now()) {
      this.pending.delete(pendingId);
      return { kind: 'expired' };
    }
    const client = this.opts.store.getClient(pending.clientId);
    if (!client) {
      this.pending.delete(pendingId);
      return { kind: 'expired' };
    }
    const retry = (status: number, message: string): LoginOutcome => ({
      kind: 'retry', status, message, pendingId, client, params: pending.params, requested,
    });

    if (logins.length === 0 || logins.length > MAX_ACCOUNTS_PER_GRANT || logins.some(l => !l.user || !l.password)) {
      return retry(401, SIGN_IN_FAILED);
    }
    if (pending.busy) return retry(401, SIGN_IN_FAILED);

    pending.busy = true;
    try {
      for (const { user, password } of logins) {
        if (!this.opts.guard.check(user, ip).ok) return retry(401, SIGN_IN_FAILED);
        // The guard reserved this attempt; settle it whatever happens.
        let result: LoginResult = 'unavailable';
        try {
          result = await this.opts.verifyLogin({ user, password });
        } finally {
          if (result === 'unavailable') this.opts.guard.release(user, ip);
          else this.opts.guard.record(user, ip, result === 'ok');
        }
        if (result === 'unavailable') return retry(503, 'The mail server could not be reached. Try again shortly.');
        if (result !== 'ok') return retry(401, SIGN_IN_FAILED);
      }
    } finally {
      pending.busy = false;
    }

    // Read is always granted; modify and send only when ticked, and send only
    // if some mailbox may send (send tools re-check per mailbox). Anything
    // else in the form is ignored.
    const scopes: Scope[] = [SCOPES.read];
    if (requested.includes(SCOPES.modify)) scopes.push(SCOPES.modify);
    if (requested.includes(SCOPES.send) && logins.some(l => this.opts.canSend(l.user))) scopes.push(SCOPES.send);

    this.pending.delete(pendingId);
    const code = newToken();
    this.codes.set(hashToken(code), {
      clientId: client.client_id,
      user: primary,
      accounts: logins.map(l => ({ user: l.user, sealedPassword: this.opts.vault.seal(l.password, passwordAad(l.user)) })),
      scopes,
      params: pending.params,
      expiresAt: this.now() + CODE_TTL_MS,
    });
    const location = new URL(pending.params.redirectUri);
    location.searchParams.set('code', code);
    if (pending.params.state !== undefined) location.searchParams.set('state', pending.params.state);
    this.completed.set(pendingId, { user: primary, location: location.href, expiresAt: this.now() + REPLAY_TTL_MS });
    this.audit('sign_in', {
      user: primary,
      accounts: logins.map(l => l.user),
      ip,
      clientId: client.client_id,
      clientName: client.client_name,
      scopes,
    });
    return { kind: 'redirect', location: location.href };
  }

  /** Re-renders the form for a pending sign-in, e.g. after a failed attempt. */
  renderRetry(res: Response, outcome: Extract<LoginOutcome, { kind: 'retry' }>): void {
    sendLoginPage(res, outcome.status, outcome);
  }

  private liveCode(client: OAuthClientInformationFull, code: string): AuthCode {
    const entry = this.codes.get(hashToken(code));
    if (!entry || entry.expiresAt <= this.now() || entry.clientId !== client.client_id) {
      throw new InvalidGrantError('invalid or expired authorization code');
    }
    return entry;
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    return this.liveCode(client, code).params.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    code: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const entry = this.liveCode(client, code);
    // Single use, whatever happens next.
    this.codes.delete(hashToken(code));
    if (redirectUri !== undefined && redirectUri !== entry.params.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    const grantResource = entry.params.resource?.href;
    if (resource && !this.isOurResource(resource)) {
      throw new InvalidTargetError('resource does not match the authorization request');
    }

    const refreshToken = newToken();
    const now = this.now();
    const grant: Grant = {
      id: randomUUID(),
      user: entry.user,
      clientId: client.client_id,
      accounts: entry.accounts,
      scopes: entry.scopes,
      resource: grantResource,
      refreshHash: hashToken(refreshToken),
      refreshExpiresAt: this.refreshExpiry(now, now),
      createdAt: now,
      lastUsedAt: now,
    };
    this.opts.store.putGrant(grant);
    this.audit('grant_created', {
      user: grant.user,
      accounts: grant.accounts.map(a => a.user),
      grantId: grant.id,
      clientId: grant.clientId,
      scopes: grant.scopes,
    });
    return this.issue(grant, refreshToken);
  }

  /** Sliding refresh expiry, capped by the grant's absolute lifetime. */
  private refreshExpiry(createdAt: number, now: number): number {
    return Math.min(now + this.opts.refreshTokenTtlSec * 1000, createdAt + this.opts.maxGrantAgeSec * 1000);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const hash = hashToken(refreshToken);
    // A refresh token that was already rotated away is being replayed: either
    // the client misbehaves or the token leaked. Revoke the grant either way.
    const replayed = this.opts.store.findGrantByPreviousRefreshHash(hash);
    if (replayed) {
      this.revokeGrant(replayed.id, 'refresh_token_reuse');
      throw new InvalidGrantError('refresh token reuse detected; sign in again');
    }
    const grant = this.opts.store.findGrantByRefreshHash(hash);
    if (!grant || grant.clientId !== client.client_id || grant.refreshExpiresAt <= this.now()) {
      throw new InvalidGrantError('invalid or expired refresh token');
    }
    if (resource && !this.isOurResource(resource)) {
      throw new InvalidTargetError('resource does not match the grant');
    }
    // Rotate: the presented refresh token is dead from here on.
    const next = newToken();
    const now = this.now();
    const updated: Grant = {
      ...grant,
      previousRefreshHash: grant.refreshHash,
      refreshHash: hashToken(next),
      refreshExpiresAt: this.refreshExpiry(grant.createdAt, now),
      lastUsedAt: now,
    };
    this.opts.store.putGrant(updated);
    return this.issue(updated, next);
  }

  private issue(grant: Grant, refreshToken: string): OAuthTokens {
    const accessToken = newToken();
    const scopes = this.effectiveScopes(grant);
    this.access.set(hashToken(accessToken), {
      grantId: grant.id,
      clientId: grant.clientId,
      scopes,
      resource: grant.resource,
      expiresAt: this.now() + this.opts.accessTokenTtlSec * 1000,
    });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.opts.accessTokenTtlSec,
      refresh_token: refreshToken,
      scope: scopes.join(' '),
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const key = hashToken(token);
    const entry = this.access.get(key);
    const grant = entry && this.opts.store.getGrant(entry.grantId);
    if (!entry || !grant || entry.expiresAt <= this.now()) {
      this.access.delete(key);
      throw new InvalidTokenError('invalid or expired access token');
    }
    const allowed = this.effectiveScopes(grant);
    return {
      token,
      clientId: entry.clientId,
      scopes: entry.scopes.filter(s => (allowed as string[]).includes(s)),
      expiresAt: Math.floor(entry.expiresAt / 1000),
      resource: new URL(entry.resource ?? this.opts.resourceUrl.href),
      extra: { grantId: entry.grantId },
    };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const hash = hashToken(request.token);
    const access = this.access.get(hash);
    if (access && access.clientId === client.client_id) {
      this.access.delete(hash);
      return;
    }
    const grant = this.opts.store.findGrantByRefreshHash(hash);
    if (grant && grant.clientId === client.client_id) this.revokeGrant(grant.id, 'client_revoked');
  }

  /** Deletes a grant and every access token minted from it. */
  revokeGrant(grantId: string, reason = 'revoked'): void {
    const grant = this.opts.store.getGrant(grantId);
    this.opts.store.deleteGrant(grantId);
    if (grant) this.audit('grant_revoked', { user: grant.user, grantId, reason });
    for (const [key, entry] of this.access) if (entry.grantId === grantId) this.access.delete(key);
  }

  /** The mailboxes an authenticated request may use, primary first. */
  accountsFor(auth: AuthInfo | undefined): string[] {
    return this.grantFor(auth).accounts.map(a => a.user);
  }

  /**
   * The IMAP credentials for one mailbox of the request's grant (the primary
   * when `account` is omitted). A mailbox outside the grant is an error:
   * a request can never reach a mailbox it did not sign in to.
   */
  credentialsFor(auth: AuthInfo | undefined, account?: string): { grantId: string; creds: ImapCredentials } {
    const grant = this.grantFor(auth);
    const wanted = account ? LoginGuard.normalize(account) : grant.user;
    const entry = grant.accounts.find(a => a.user === wanted);
    if (!entry) {
      throw new Error(`mailbox ${wanted} is not part of this connection; available: ${grant.accounts.map(a => a.user).join(', ')}`);
    }
    return {
      grantId: grant.id,
      creds: { user: entry.user, password: this.opts.vault.open(entry.sealedPassword, passwordAad(entry.user)) },
    };
  }

  private grantFor(auth: AuthInfo | undefined): Grant {
    const grantId = auth?.extra?.grantId;
    const grant = typeof grantId === 'string' ? this.opts.store.getGrant(grantId) : undefined;
    if (!grant) throw new InvalidTokenError('grant no longer exists');
    return grant;
  }

  /** Issues a single-use link for adding a mailbox to the request's connection. */
  createAddMailboxLink(auth: AuthInfo | undefined): { url: string; expiresAt: string } {
    const grant = this.grantFor(auth);
    if (grant.accounts.length >= MAX_ACCOUNTS_PER_GRANT) {
      throw new Error(`this connection already has the maximum of ${MAX_ACCOUNTS_PER_GRANT} mailboxes`);
    }
    this.sweep();
    const token = newToken();
    const expiresAt = this.now() + ADD_LINK_TTL_MS;
    this.addLinks.set(hashToken(token), { grantId: grant.id, expiresAt });
    this.audit('add_link_created', { user: grant.user, grantId: grant.id });
    const url = new URL('/add-mailbox', this.opts.resourceUrl);
    url.searchParams.set('t', token);
    return { url: url.href, expiresAt: new Date(expiresAt).toISOString() };
  }

  private liveAddLink(token: string): { link: AddLink; grant: Grant } | undefined {
    const link = this.addLinks.get(hashToken(token));
    const grant = link && this.opts.store.getGrant(link.grantId);
    if (!link || !grant || link.expiresAt <= this.now()) {
      this.addLinks.delete(hashToken(token));
      return undefined;
    }
    return { link, grant };
  }

  /** What the add-mailbox page shows: the connection the link belongs to. */
  addLinkView(token: string): { primary: string; accounts: string[] } | undefined {
    const live = this.liveAddLink(token);
    return live && { primary: live.grant.user, accounts: live.grant.accounts.map(a => a.user) };
  }

  /**
   * Adds a mailbox through a link: same allowlist, guard and IMAP proof as
   * sign-in. The link is consumed only on success, so a typo can be retried
   * within its lifetime; one attempt runs at a time.
   */
  async completeAddMailbox(token: string, rawUser: string, password: string, ip: string): Promise<AddMailboxOutcome> {
    const live = this.liveAddLink(token);
    if (!live) return { kind: 'expired' };
    const { link, grant } = live;
    const user = LoginGuard.normalize(rawUser);
    if (grant.accounts.some(a => a.user === user)) {
      return { kind: 'retry', status: 409, message: `${user} is already part of this connection.` };
    }
    if (grant.accounts.length >= MAX_ACCOUNTS_PER_GRANT) {
      return { kind: 'retry', status: 409, message: `This connection already has the maximum of ${MAX_ACCOUNTS_PER_GRANT} mailboxes.` };
    }
    if (!user || !password || link.busy) return { kind: 'retry', status: 401, message: SIGN_IN_FAILED };
    if (!this.opts.guard.check(user, ip).ok) return { kind: 'retry', status: 401, message: SIGN_IN_FAILED };

    link.busy = true;
    let result: LoginResult = 'unavailable';
    try {
      result = await this.opts.verifyLogin({ user, password });
    } finally {
      link.busy = false;
      if (result === 'unavailable') this.opts.guard.release(user, ip);
      else this.opts.guard.record(user, ip, result === 'ok');
    }
    if (result === 'unavailable') return { kind: 'retry', status: 503, message: 'The mail server could not be reached. Try again shortly.' };
    if (result !== 'ok') return { kind: 'retry', status: 401, message: SIGN_IN_FAILED };

    // Re-read: the grant may have changed while the IMAP check ran.
    const current = this.opts.store.getGrant(grant.id);
    if (!current) return { kind: 'expired' };
    if (!current.accounts.some(a => a.user === user)) {
      current.accounts.push({ user, sealedPassword: this.opts.vault.seal(password, passwordAad(user)) });
      this.opts.store.putGrant(current);
    }
    this.addLinks.delete(hashToken(token));
    this.audit('mailbox_added', { user: current.user, added: user, grantId: current.id, ip });
    return { kind: 'added', account: user, accounts: current.accounts.map(a => a.user) };
  }

  /** Removes a mailbox from the request's connection. The primary mailbox cannot be removed. */
  removeMailbox(auth: AuthInfo | undefined, address: string): string[] {
    const grant = this.grantFor(auth);
    const user = LoginGuard.normalize(address);
    if (user === grant.user) {
      throw new Error(`${user} is the primary mailbox of this connection; disconnect the connector in Claude to remove it`);
    }
    if (!grant.accounts.some(a => a.user === user)) throw new Error(`${user} is not part of this connection`);
    grant.accounts = grant.accounts.filter(a => a.user !== user);
    this.opts.store.putGrant(grant);
    this.audit('mailbox_removed', { user: grant.user, removed: user, grantId: grant.id });
    return grant.accounts.map(a => a.user);
  }

  private sweep(): void {
    const now = this.now();
    for (const [k, v] of this.addLinks) if (v.expiresAt <= now) this.addLinks.delete(k);
    for (const [k, v] of this.pending) if (v.expiresAt <= now) this.pending.delete(k);
    for (const [k, v] of this.codes) if (v.expiresAt <= now) this.codes.delete(k);
    for (const [k, v] of this.completed) if (v.expiresAt <= now) this.completed.delete(k);
    for (const [k, v] of this.access) if (v.expiresAt <= now) this.access.delete(k);
  }
}

function sendLoginPage(
  res: Response,
  status: number,
  view: {
    pendingId: string;
    client: OAuthClientInformationFull;
    params: AuthorizationParams;
    message?: string;
    requested?: Scope[];
  },
): void {
  res
    .status(status)
    .set({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': pageCsp(view.params.redirectUri),
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    })
    .send(
      renderLoginPage({
        pendingId: view.pendingId,
        clientName: view.client.client_name ?? 'An MCP client',
        redirectUri: view.params.redirectUri,
        message: view.message,
        requested: view.requested ?? [],
      }),
    );
}
