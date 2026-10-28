import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Vault } from '../src/crypto.js';
import { Store } from '../src/store.js';
import { LoginGuard } from '../src/login-guard.js';
import { GatewayProvider } from '../src/provider.js';
import { createApp } from '../src/server.js';
import type { ImapCredentials, LoginResult } from '../src/imap.js';
import type { MailReader } from '../src/mail.js';

const PASSWORDS: Record<string, string> = { 'alice@example.com': 'alice-pw', 'bob@example.com': 'bob-pw' };
const REDIRECT = 'http://127.0.0.1:9/callback';

let server: Server;
let base: string;
let stateFile: string;
let loginCalls: string[];
let readerCalls: ImapCredentials[];
let failAuthFor: string | undefined;

const fakeReader = {
  async search(creds: ImapCredentials) {
    readerCalls.push(creds);
    if (creds.user === failAuthFor) throw Object.assign(new Error('auth failed'), { authenticationFailed: true });
    return { total: 1, messages: [{ uid: 1, subject: `mail for ${creds.user}`, seen: false, flagged: false }] };
  },
} as unknown as MailReader;

beforeAll(async () => {
  stateFile = join(mkdtempSync(join(tmpdir(), 'gw-')), 'state.json');
  server = createServer();
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  base = `http://127.0.0.1:${port}`;
  const publicUrl = new URL(base);
  const resourceUrl = new URL('/mcp', publicUrl);
  const provider = new GatewayProvider({
    store: new Store(stateFile),
    vault: new Vault(randomBytes(32)),
    guard: new LoginGuard(new Set(Object.keys(PASSWORDS))),
    resourceUrl,
    verifyLogin: async ({ user, password }): Promise<LoginResult> => {
      loginCalls.push(user);
      return PASSWORDS[user] === password ? 'ok' : 'bad_credentials';
    },
    accessTokenTtlSec: 3600,
    refreshTokenTtlSec: 86400,
  });
  server.on('request', createApp({ provider, reader: fakeReader, publicUrl, resourceUrl, version: 'test' }));
});

afterAll(() => new Promise<void>(r => server.close(() => r())));

beforeEach(() => {
  loginCalls = [];
  readerCalls = [];
  failAuthFor = undefined;
});

async function register(): Promise<string> {
  const res = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none', client_name: 'Test client' }),
  });
  expect(res.status).toBe(201);
  return ((await res.json()) as { client_id: string }).client_id;
}

async function startAuthorize(clientId: string) {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const url = new URL('/authorize', base);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'st-1',
    scope: 'mail.read',
    resource: `${base}/mcp`,
  }).toString();
  const res = await fetch(url, { redirect: 'manual' });
  expect(res.status).toBe(200);
  const html = await res.text();
  const pending = html.match(/name="pending" value="([^"]+)"/)?.[1];
  expect(pending).toBeTruthy();
  expect(html).toContain('Test client');
  return { verifier, pending: pending! };
}

function login(pending: string, user: string, password: string) {
  return fetch(`${base}/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ pending, user, password }).toString(),
  });
}

async function token(params: Record<string, string>) {
  const res = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, string> };
}

async function signIn(user: string) {
  const clientId = await register();
  const { verifier, pending } = await startAuthorize(clientId);
  const res = await login(pending, user, PASSWORDS[user]!);
  expect(res.status).toBe(302);
  const location = new URL(res.headers.get('location')!);
  expect(location.origin + location.pathname).toBe(REDIRECT);
  expect(location.searchParams.get('state')).toBe('st-1');
  const code = location.searchParams.get('code')!;
  const tokens = await token({
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id: clientId,
    redirect_uri: REDIRECT,
    resource: `${base}/mcp`,
  });
  expect(tokens.status).toBe(200);
  return { clientId, code, verifier, ...tokens.body } as Record<string, string>;
}

async function mcp(accessToken: string | undefined, body: unknown) {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  const data = text
    .split('\n')
    .filter(l => l.startsWith('data: '))
    .map(l => JSON.parse(l.slice(6)));
  return { res, message: data[0] ?? (text ? JSON.parse(text) : undefined) };
}

const callSearch = (accessToken: string) =>
  mcp(accessToken, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'search_mail', arguments: {} } });

describe('OAuth + MCP flow', () => {
  it('publishes protected-resource and authorization-server metadata', async () => {
    const prm = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
    expect(prm).toMatchObject({ resource: `${base}/mcp`, authorization_servers: [`${base}/`] });
    const as = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
    expect(as).toMatchObject({ registration_endpoint: `${base}/register`, code_challenge_methods_supported: ['S256'] });
  });

  it('rejects /mcp without a token and points at the metadata', async () => {
    const { res } = await mcp(undefined, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('resource_metadata=');
  });

  it('signs in with IMAP credentials and serves only that user\'s mailbox', async () => {
    const alice = await signIn('alice@example.com');
    const bob = await signIn('bob@example.com');

    const list = await mcp(alice.access_token, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(list.res.status).toBe(200);
    expect(list.message.result.tools.map((t: { name: string }) => t.name).sort()).toEqual(
      ['list_folders', 'read_attachment', 'read_message', 'read_thread', 'search_mail'],
    );

    const a = await callSearch(alice.access_token);
    const b = await callSearch(bob.access_token);
    expect(a.message.result.content[0].text).toContain('mail for alice@example.com');
    expect(b.message.result.content[0].text).toContain('mail for bob@example.com');
    expect(readerCalls).toEqual([
      { user: 'alice@example.com', password: 'alice-pw' },
      { user: 'bob@example.com', password: 'bob-pw' },
    ]);
  });

  it('never stores passwords or tokens in plaintext', async () => {
    const alice = await signIn('alice@example.com');
    const state = readFileSync(stateFile, 'utf8');
    expect(state).not.toContain('alice-pw');
    expect(state).not.toContain(alice.access_token);
    expect(state).not.toContain(alice.refresh_token);
  });

  it('makes authorization codes single-use', async () => {
    const alice = await signIn('alice@example.com');
    const again = await token({
      grant_type: 'authorization_code',
      code: alice.code!,
      code_verifier: alice.verifier!,
      client_id: alice.clientId!,
      redirect_uri: REDIRECT,
    });
    expect(again.status).toBe(400);
    expect(again.body.error).toBe('invalid_grant');
  });

  it('rotates refresh tokens', async () => {
    const alice = await signIn('alice@example.com');
    const first = await token({ grant_type: 'refresh_token', refresh_token: alice.refresh_token!, client_id: alice.clientId! });
    expect(first.status).toBe(200);
    expect(first.body.refresh_token).not.toBe(alice.refresh_token);
    const replay = await token({ grant_type: 'refresh_token', refresh_token: alice.refresh_token!, client_id: alice.clientId! });
    expect(replay.status).toBe(400);
    expect((await callSearch(first.body.access_token!)).res.status).toBe(200);
  });

  it('refuses unknown addresses without contacting the mail server', async () => {
    const clientId = await register();
    const { pending } = await startAuthorize(clientId);
    const res = await login(pending, 'mallory@example.com', 'whatever');
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('Wrong address or password');
    expect(loginCalls).toEqual([]);
  });

  it('answers a double submit with the same redirect, for the same address only', async () => {
    const clientId = await register();
    const { pending } = await startAuthorize(clientId);
    const first = await login(pending, 'alice@example.com', 'alice-pw');
    expect(first.status).toBe(302);
    const again = await login(pending, 'Alice@Example.com', 'alice-pw');
    expect(again.status).toBe(302);
    expect(again.headers.get('location')).toBe(first.headers.get('location'));
    const other = await login(pending, 'bob@example.com', 'bob-pw');
    expect(other.status).toBe(400);
    // The duplicate did not cost a second IMAP login.
    expect(loginCalls).toEqual(['alice@example.com']);
  });

  it('serves the sign-in page with a hash-pinned script CSP', async () => {
    const clientId = await register();
    const url = new URL('/authorize', base);
    url.search = new URLSearchParams({
      response_type: 'code', client_id: clientId, redirect_uri: REDIRECT,
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256',
    }).toString();
    const res = await fetch(url, { redirect: 'manual' });
    expect(res.headers.get('content-security-policy')).toMatch(/script-src 'sha256-[A-Za-z0-9+/=]+'/);
    expect(await res.text()).toContain('<script>');
  });

  it('refuses a wrong password with the same message', async () => {
    const clientId = await register();
    const { pending } = await startAuthorize(clientId);
    const res = await login(pending, 'alice@example.com', 'wrong');
    expect(res.status).toBe(401);
    expect(await res.text()).toContain('Wrong address or password');
    expect(loginCalls).toEqual(['alice@example.com']);
  });

  it('drops the grant when the mail server rejects stored credentials', async () => {
    const bob = await signIn('bob@example.com');
    failAuthFor = 'bob@example.com';
    const failed = await callSearch(bob.access_token!);
    expect(failed.message.result.isError).toBe(true);
    expect(failed.message.result.content[0].text).toContain('reconnect');
    const after = await callSearch(bob.access_token!);
    expect(after.res.status).toBe(401);
  });

  it('rejects an unknown resource indicator', async () => {
    const clientId = await register();
    const url = new URL('/authorize', base);
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: REDIRECT,
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
      resource: 'https://elsewhere.example/mcp',
    }).toString();
    const res = await fetch(url, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('invalid_target');
  });
});
