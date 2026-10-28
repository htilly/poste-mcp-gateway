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
  InvalidGrantError,
  InvalidTargetError,
  InvalidTokenError,
  TooManyRequestsError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { Vault, hashToken, newToken } from './crypto.js';
import type { Grant, Store } from './store.js';
import { LoginGuard } from './login-guard.js';
import type { ImapCredentials, LoginResult } from './imap.js';
import { LOGIN_PAGE_CSP, renderLoginPage } from './login-page.js';

export const SCOPE = 'mail.read';

const PENDING_TTL_MS = 10 * 60 * 1000;
const CODE_TTL_MS = 60 * 1000;
/** How long a finished sign-in answers a duplicate submit with the same redirect. */
const REPLAY_TTL_MS = 60 * 1000;

interface PendingAuthorization {
  clientId: string;
  params: AuthorizationParams;
  expiresAt: number;
}

interface AuthCode {
  clientId: string;
  user: string;
  sealedPassword: string;
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
  accessTokenTtlSec: number;
  refreshTokenTtlSec: number;
  now?: () => number;
}

export type LoginOutcome =
  | { kind: 'redirect'; location: string }
  | { kind: 'retry'; status: number; message: string; pendingId: string; client: OAuthClientInformationFull; params: AuthorizationParams }
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

  constructor(private readonly opts: ProviderOptions) {
    this.now = opts.now ?? Date.now;
  }

  get clientsStore(): OAuthRegisteredClientsStore {
    const { store } = this.opts;
    return {
      getClient: id => store.getClient(id),
      registerClient: client => {
        const full = client as OAuthClientInformationFull;
        try {
          store.addClient(full);
        } catch {
          throw new TooManyRequestsError('client registration limit reached');
        }
        return full;
      },
    };
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
  async completeLogin(pendingId: string, user: string, password: string, ip: string): Promise<LoginOutcome> {
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
      kind: 'retry', status, message, pendingId, client, params: pending.params,
    });

    const account = LoginGuard.normalize(user);
    const decision = this.opts.guard.check(account, ip);
    if (!decision.ok) {
      if (decision.reason === 'not_allowed') return retry(401, 'Wrong address or password.');
      return retry(429, 'Too many failed sign-ins. Try again in 15 minutes.');
    }
    if (!password) return retry(401, 'Wrong address or password.');

    const result = await this.opts.verifyLogin({ user: account, password });
    if (result === 'unavailable') return retry(503, 'The mail server could not be reached. Try again shortly.');
    this.opts.guard.record(account, ip, result === 'ok');
    if (result !== 'ok') return retry(401, 'Wrong address or password.');

    this.pending.delete(pendingId);
    const code = newToken();
    this.codes.set(hashToken(code), {
      clientId: client.client_id,
      user: account,
      sealedPassword: this.opts.vault.seal(password, passwordAad(account)),
      params: pending.params,
      expiresAt: this.now() + CODE_TTL_MS,
    });
    const location = new URL(pending.params.redirectUri);
    location.searchParams.set('code', code);
    if (pending.params.state !== undefined) location.searchParams.set('state', pending.params.state);
    this.completed.set(pendingId, { user: account, location: location.href, expiresAt: this.now() + REPLAY_TTL_MS });
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
      scopes: [SCOPE],
      resource: grantResource,
      refreshHash: hashToken(refreshToken),
      refreshExpiresAt: now + this.opts.refreshTokenTtlSec * 1000,
      createdAt: now,
      lastUsedAt: now,
    };
    this.opts.store.putGrant(grant);
    return this.issue(grant, refreshToken);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    _scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const grant = this.opts.store.findGrantByRefreshHash(hashToken(refreshToken));
    if (!grant || grant.clientId !== client.client_id || grant.refreshExpiresAt <= this.now()) {
      throw new InvalidGrantError('invalid or expired refresh token');
    }
    if (resource && resource.href !== (grant.resource ?? this.opts.resourceUrl.href)) {
      throw new InvalidTargetError('resource does not match the grant');
    }
    // Rotate: the presented refresh token is dead from here on.
    const next = newToken();
    const now = this.now();
    this.opts.store.putGrant({
      ...grant,
      refreshHash: hashToken(next),
      refreshExpiresAt: now + this.opts.refreshTokenTtlSec * 1000,
      lastUsedAt: now,
    });
    return this.issue(grant, next);
  }

  private issue(grant: Grant, refreshToken: string): OAuthTokens {
    const accessToken = newToken();
    this.access.set(hashToken(accessToken), {
      grantId: grant.id,
      clientId: grant.clientId,
      scopes: grant.scopes,
      resource: grant.resource,
      expiresAt: this.now() + this.opts.accessTokenTtlSec * 1000,
    });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.opts.accessTokenTtlSec,
      refresh_token: refreshToken,
      scope: grant.scopes.join(' '),
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const key = hashToken(token);
    const entry = this.access.get(key);
    if (!entry || entry.expiresAt <= this.now() || !this.opts.store.getGrant(entry.grantId)) {
      this.access.delete(key);
      throw new InvalidTokenError('invalid or expired access token');
    }
    return {
      token,
      clientId: entry.clientId,
      scopes: entry.scopes,
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
    if (grant && grant.clientId === client.client_id) this.revokeGrant(grant.id);
  }

  /** Deletes a grant and every access token minted from it. */
  revokeGrant(grantId: string): void {
    this.opts.store.deleteGrant(grantId);
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
  view: { pendingId: string; client: OAuthClientInformationFull; params: AuthorizationParams; message?: string },
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
        redirectHost: new URL(view.params.redirectUri).host,
        message: view.message,
      }),
    );
}
