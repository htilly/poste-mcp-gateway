import express, { type Express } from 'express';
import { rateLimit } from 'express-rate-limit';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { GatewayProvider } from './provider.js';
import { registerTools } from './tools.js';
import type { MailReader } from './mail.js';
import type { MailWriter } from './mail-write.js';
import type { MailSender } from './smtp.js';
import { ALL_SCOPES, SCOPES, isScope, type Scope } from './scopes.js';
import { silentAudit, type Audit } from './audit.js';
import { LOGIN_PAGE_CSP, renderAddMailboxPage } from './login-page.js';
import type { Response } from 'express';

function sendPage(res: Response, status: number, html: string): void {
  res
    .status(status)
    .set({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': LOGIN_PAGE_CSP,
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    })
    .send(html);
}

const LINK_EXPIRED = 'This link has expired or was already used. Ask Claude for a new one (add_mailbox).';

export interface AppDeps {
  provider: GatewayProvider;
  reader: MailReader;
  writer?: MailWriter;
  sender?: MailSender;
  /** Issuer, e.g. https://mail.example.com:8443 */
  publicUrl: URL;
  /** The MCP endpoint, publicUrl + /mcp */
  resourceUrl: URL;
  version: string;
  audit?: Audit;
  /** POST /login requests per IP per 15 minutes. */
  loginRateLimit?: number;
  /** Client registrations per IP per hour (the SDK's default is 20). */
  registrationRateLimit?: number;
}

export function createApp({
  provider,
  reader,
  writer,
  sender,
  publicUrl,
  resourceUrl,
  version,
  audit = silentAudit,
  loginRateLimit = 20,
  registrationRateLimit = 20,
}: AppDeps): Express {
  const app = express();
  app.disable('x-powered-by');
  // Exactly one reverse proxy sits in front; req.ip is then the real client,
  // which the login guard and the SDK's rate limiters key on.
  app.set('trust proxy', 1);

  if (publicUrl.protocol === 'https:') {
    app.use((_req, res, next) => {
      res.set('Strict-Transport-Security', 'max-age=31536000');
      next();
    });
  }

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true });
  });

  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: publicUrl,
      resourceServerUrl: resourceUrl,
      scopesSupported: [...ALL_SCOPES],
      resourceName: 'Mail',
      clientRegistrationOptions: { rateLimit: { max: registrationRateLimit } },
    }),
  );

  // Coarse request cap in front of the login guard's own accounting.
  const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: loginRateLimit, standardHeaders: 'draft-7', legacyHeaders: false });

  app.post('/login', loginLimiter, express.urlencoded({ extended: false, limit: '4kb' }), async (req, res) => {
    const pending = String(req.body?.pending ?? '');
    // Rows of the form: user/password pairs, the first being the primary mailbox.
    const users = [req.body?.user ?? []].flat().map(String);
    const passwords = [req.body?.password ?? []].flat().map(String);
    const logins = users.map((user, i) => ({ user, password: passwords[i] ?? '' }));
    const user = users[0] ?? '';
    const requested: Scope[] = [req.body?.scope ?? []].flat().map(String).filter(isScope);
    const outcome = await provider.completeLogin(pending, logins, req.ip ?? 'unknown', requested);
    switch (outcome.kind) {
      case 'redirect':
        res.set('Cache-Control', 'no-store').redirect(302, outcome.location);
        return;
      case 'retry':
        audit('sign_in_refused', { user: user.trim().toLowerCase().slice(0, 254), ip: req.ip, status: outcome.status });
        provider.renderRetry(res, outcome);
        return;
      case 'expired':
        res.status(400).type('text/plain').send('This sign-in link has expired. Start again from your MCP client.');
        return;
    }
  });

  // add_mailbox links: attach one more proven mailbox to an existing connection.
  app.get('/add-mailbox', (req, res) => {
    const token = String(req.query.t ?? '');
    const view = provider.addLinkView(token);
    if (!view) {
      res.status(400).type('text/plain').send(LINK_EXPIRED);
      return;
    }
    sendPage(res, 200, renderAddMailboxPage({ token, accounts: view.accounts }));
  });

  app.post('/add-mailbox', loginLimiter, express.urlencoded({ extended: false, limit: '4kb' }), async (req, res) => {
    const token = String(req.body?.t ?? '');
    const user = String(req.body?.user ?? '');
    const outcome = await provider.completeAddMailbox(token, user, String(req.body?.password ?? ''), req.ip ?? 'unknown');
    switch (outcome.kind) {
      case 'added':
        sendPage(res, 200, renderAddMailboxPage({ token: '', accounts: outcome.accounts, added: outcome.account }));
        return;
      case 'retry': {
        audit('add_mailbox_refused', { user: user.trim().toLowerCase().slice(0, 254), ip: req.ip, status: outcome.status });
        const view = provider.addLinkView(token);
        if (!view) break;
        sendPage(res, outcome.status, renderAddMailboxPage({ token, accounts: view.accounts, message: outcome.message }));
        return;
      }
      case 'expired':
        break;
    }
    res.status(400).type('text/plain').send(LINK_EXPIRED);
  });

  const bearer = requireBearerAuth({
    verifier: provider,
    requiredScopes: [SCOPES.read],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceUrl),
  });

  // Stateless streamable HTTP: a fresh server and transport per request, so no
  // MCP session state is shared between users or requests.
  app.post(resourceUrl.pathname, express.json({ limit: '1mb' }), bearer, async (req, res) => {
    const server = new McpServer({ name: 'poste-mcp-gateway', version });
    registerTools(server, {
      reader,
      writer,
      sender,
      audit,
      scopes: (req.auth?.scopes ?? []).filter(isScope),
      credentialsFor: (auth, account) => provider.credentialsFor(auth, account),
      accountsFor: auth => provider.accountsFor(auth),
      createAddMailboxLink: auth => provider.createAddMailboxLink(auth),
      removeMailbox: (auth, address) => provider.removeMailbox(auth, address),
      canSend: user => provider.canSend(user),
      revokeGrant: id => provider.revokeGrant(id),
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error('[mcp] request failed:', err instanceof Error ? err.message : err);
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
      }
    }
  });

  app.all(resourceUrl.pathname, (_req, res) => {
    res.status(405).set('Allow', 'POST').json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null });
  });

  return app;
}
