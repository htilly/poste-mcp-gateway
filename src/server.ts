import express, { type Express } from 'express';
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
}

export function createApp({ provider, reader, writer, sender, publicUrl, resourceUrl, version }: AppDeps): Express {
  const app = express();
  app.disable('x-powered-by');
  // Exactly one reverse proxy sits in front; req.ip is then the real client,
  // which the login guard and the SDK's rate limiters key on.
  app.set('trust proxy', 1);

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
    }),
  );

  app.post('/login', express.urlencoded({ extended: false, limit: '4kb' }), async (req, res) => {
    const pending = String(req.body?.pending ?? '');
    const user = String(req.body?.user ?? '');
    const password = String(req.body?.password ?? '');
    const requested: Scope[] = [req.body?.scope ?? []].flat().map(String).filter(isScope);
    const outcome = await provider.completeLogin(pending, user, password, req.ip ?? 'unknown', requested);
    switch (outcome.kind) {
      case 'redirect':
        res.set('Cache-Control', 'no-store').redirect(302, outcome.location);
        return;
      case 'retry':
        console.error(`[login] refused user=${user.trim().toLowerCase()} ip=${req.ip} status=${outcome.status}`);
        provider.renderRetry(res, outcome);
        return;
      case 'expired':
        res.status(400).type('text/plain').send('This sign-in link has expired. Start again from your MCP client.');
        return;
    }
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
      scopes: (req.auth?.scopes ?? []).filter(isScope),
      credentialsFor: auth => provider.credentialsFor(auth),
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
