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
import type { Grant, Store } from './store.js';
import { LoginGuard } from './login-guard.js';
import type { ImapCredentials, LoginResult } from './imap.js';
import { LOGIN_PAGE_CSP, renderLoginPage } from './login-page.js';
import { SCOPES, type Scope } from './scopes.js';
import { silentAudit, type Audit } from './audit.js';

const PENDING_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
/** How long a finished sign-in answers a duplicate submit with the same redirect. */
const REPLAY_TTL_MS = 60 * 1000;

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
  user: string;
  sealedPassword: string;
  scopes: Scope[];
  params: AuthorizationParams;
  expiresAt: number;
}

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
    return grant.scopes.filter(s => s !== SCOPES.send || this.opts.canSend(grant.user)) as Scope[];
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (params.resource && params.resource.href !== this.opts.resourceUrl.href) {
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
   * Handles the sign-in form. Order matters: the guard runs before any IMAP
   * traffic, and its verdict for unknown addresses is indistinguishable from
   * a wrong password.
   */
  async completeLogin(
    pendingId: string,
    user: string,
    password: string,
    ip: string,
    requested: Scope[] = [],
  ): Promise<LoginOutcome> {
    // A second submit of a form that already signed in (double click, Enter
    // plus click) gets the same redirect instead of "expired": the browser
    // usually abandoned the first response, and with it the code.
    const done = this.completed.get(pendingId);
    if (done && done.expiresAt > this.now() && done.user === LoginGuard.normalize(user)) {
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

    const account = LoginGuard.normalize(user);
    if (!password || pending.busy) return retry(401, SIGN_IN_FAILED);
    const decision = this.opts.guard.check(account, ip);
    if (!decision.ok) return retry(401, SIGN_IN_FAILED);

    // The guard reserved this attempt; settle it whatever happens.
    pending.busy = true;
    let result: LoginResult = 'unavailable';
    try {
      result = await this.opts.verifyLogin({ user: account, password });
    } finally {
      pending.busy = false;
      if (result === 'unavailable') this.opts.guard.release(account, ip);
      else this.opts.guard.record(account, ip, result === 'ok');
    }
    if (result === 'unavailable') return retry(503, 'The mail server could not be reached. Try again shortly.');
    if (result !== 'ok') return retry(401, SIGN_IN_FAILED);

    // Read is always granted; modify and send only when ticked, and send only
    // for addresses allowed to send. Anything else in the form is ignored.
    const scopes: Scope[] = [SCOPES.read];
    if (requested.includes(SCOPES.modify)) scopes.push(SCOPES.modify);
    if (requested.includes(SCOPES.send) && this.opts.canSend(account)) scopes.push(SCOPES.send);

    this.pending.delete(pendingId);
    const code = newToken();
    this.codes.set(hashToken(code), {
      clientId: client.client_id,
      user: account,
      sealedPassword: this.opts.vault.seal(password, passwordAad(account)),
      scopes,
      params: pending.params,
      expiresAt: this.now() + CODE_TTL_MS,
    });
    const location = new URL(pending.params.redirectUri);
    location.searchParams.set('code', code);
    if (pending.params.state !== undefined) location.searchParams.set('state', pending.params.state);
    this.completed.set(pendingId, { user: account, location: location.href, expiresAt: this.now() + REPLAY_TTL_MS });
    this.audit('sign_in', { user: account, ip, clientId: client.client_id, clientName: client.client_name, scopes });
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
    if (resource && resource.href !== (grantResource ?? this.opts.resourceUrl.href)) {
      throw new InvalidTargetError('resource does not match the authorization request');
    }

    const refreshToken = newToken();
    const now = this.now();
    const grant: Grant = {
      id: randomUUID(),
      user: entry.user,
      clientId: client.client_id,
      sealedPassword: entry.sealedPassword,
      scopes: entry.scopes,
      resource: grantResource,
      refreshHash: hashToken(refreshToken),
      refreshExpiresAt: this.refreshExpiry(now, now),
      createdAt: now,
      lastUsedAt: now,
    };
    this.opts.store.putGrant(grant);
    this.audit('grant_created', { user: grant.user, grantId: grant.id, clientId: grant.clientId, scopes: grant.scopes });
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
    if (resource && resource.href !== (grant.resource ?? this.opts.resourceUrl.href)) {
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

  /** The IMAP credentials behind an authenticated request. */
  credentialsFor(auth: AuthInfo | undefined): { grantId: string; creds: ImapCredentials } {
    const grantId = auth?.extra?.grantId;
    const grant = typeof grantId === 'string' ? this.opts.store.getGrant(grantId) : undefined;
    if (!grant) throw new InvalidTokenError('grant no longer exists');
    return {
      grantId: grant.id,
      creds: { user: grant.user, password: this.opts.vault.open(grant.sealedPassword, passwordAad(grant.user)) },
    };
  }

  private sweep(): void {
    const now = this.now();
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
      'Content-Security-Policy': LOGIN_PAGE_CSP,
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
