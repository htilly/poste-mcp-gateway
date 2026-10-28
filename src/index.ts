import { readFileSync } from 'node:fs';
import { isAllowedRedirectUri, loadConfig } from './config.js';
import { Vault } from './crypto.js';
import { Store } from './store.js';
import { LoginGuard } from './login-guard.js';
import { GatewayProvider } from './provider.js';
import { MailReader } from './mail.js';
import { MailWriter } from './mail-write.js';
import { MailSender } from './smtp.js';
import { audit } from './audit.js';
import { verifyLogin, type ImapTarget } from './imap.js';
import { createApp } from './server.js';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };

const config = loadConfig();
const target: ImapTarget = { host: config.imapHost, port: config.imapPort, servername: config.imapServername };
const store = new Store(config.stateFile);
const resourceUrl = new URL('/mcp', config.publicUrl);

const provider = new GatewayProvider({
  store,
  vault: new Vault(config.vaultKey),
  guard: new LoginGuard(config.allowedUsers),
  resourceUrl,
  verifyLogin: creds => verifyLogin(target, creds),
  canSend: user => config.sendUsers.has(user),
  allowRedirectUri: uri => isAllowedRedirectUri(uri, config.allowedRedirectHosts),
  maxGrantAgeSec: config.maxGrantAgeSec,
  audit,
  accessTokenTtlSec: config.accessTokenTtlSec,
  refreshTokenTtlSec: config.refreshTokenTtlSec,
});

const reader = new MailReader(target);
const writer = new MailWriter(target);
const sender = new MailSender(
  { host: config.smtpHost, port: config.smtpPort, secure: config.smtpSecure, servername: config.smtpHost },
  writer,
  {
    perHour: config.sendLimitPerHour,
    newRecipients: config.sendNewRecipients,
    previouslySentTo: (creds, addresses) => reader.previouslySentTo(creds, addresses),
  },
  audit,
);
const app = createApp({ provider, reader, writer, sender, publicUrl: config.publicUrl, resourceUrl, version, audit });

store.pruneExpiredGrants();
// Removing an address from ALLOWED_USERS and restarting is how access is revoked.
const revoked = store.deleteGrantsWhere(g => !config.allowedUsers.has(g.user));
if (revoked) console.error(`[gateway] revoked ${revoked} grant(s) for addresses no longer allowed`);
setInterval(() => store.pruneExpiredGrants(), 6 * 3600 * 1000).unref();

const server = app.listen(config.listenPort, config.listenHost, () => {
  console.error(
    `[gateway] v${version} listening on ${config.listenHost}:${config.listenPort}; ` +
      `resource ${resourceUrl.href}; IMAP ${config.imapHost}:${config.imapPort}; ${config.allowedUsers.size} allowed user(s)`,
  );
});

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
