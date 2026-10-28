# poste-mcp-gateway

A read-only MCP gateway into poste.io mailboxes. A small, invited group of
mailbox owners add `https://mail.example.com:8443/mcp` as a custom connector
in Claude, sign in once with their own poste.io address and password, and
Claude can then search and read **their** mailbox. It cannot send, move,
delete or change anything.

What it has to achieve, and why, is in [docs/requirements.md](docs/requirements.md).

## How it works

```
Claude ──HTTPS──▶ Caddy :8443 ──▶ gateway :8080 ──IMAPS──▶ poste.io (IMAPS :993)
                  (TLS, DNS-01)    OAuth 2.1 + MCP           EXAMINE + BODY.PEEK only
```

- **Sign-in is an IMAP login.** The OAuth authorize step shows a login page;
  the gateway checks the address against `ALLOWED_USERS` and then logs in to
  poste.io with what the user typed. Success issues an authorization code.
  There are no gateway accounts and no other way in.
- **One grant per user and client.** The user's IMAP password is sealed with
  AES-256-GCM (key from a Docker secret, bound to the user) and stored with
  the grant. Tokens are stored hashed. Access tokens live 1 hour in memory;
  refresh tokens rotate on every use and expire after 30 days.
- **Every tool call opens a short IMAP session as that user,** opens the
  folder with `EXAMINE` and fetches with `BODY.PEEK`, then logs out. Nothing
  is mirrored or cached.
- **Stateless MCP over streamable HTTP:** a fresh server per request, so
  nothing is shared between users.

OAuth endpoints (metadata, dynamic client registration, PKCE, token,
revocation) come from the MCP TypeScript SDK's `mcpAuthRouter`; this project
supplies the provider (`src/provider.ts`).

## Tools

| Tool | Does |
|---|---|
| `list_folders` | Folders with message and unread counts |
| `search_mail` | IMAP SEARCH in one folder (text, from, to, subject, since, before, unseen), newest first, max 50 |
| `read_message` | Headers, body as text/Markdown (20k chars max), attachment list |
| `read_thread` | Messages in the same conversation (Message-ID / In-Reply-To / References) |
| `read_attachment` | Images as images, text formats as text (50k chars), other binaries metadata only; 5 MB max |

All are annotated read-only. Mail content is returned inside
`<<<UNTRUSTED EMAIL CONTENT ...>>>` markers; markers inside the mail are
neutralized so a message cannot close the block early.

## Security model

- **Read-only is structural.** `src/` contains no mutating IMAP call and no
  SMTP code; `test/readonly.test.ts` fails the build if one appears. Mailboxes
  are opened with `EXAMINE`, so the server refuses changes too (verified
  against Dovecot, which poste.io runs, in `test/live.test.ts`).
- **Prompt injection.** Any email can contain text aimed at Claude. Since
  nothing can be sent or changed, the worst a malicious message can do is be
  read. Treat what Claude reports from mail with the same care as the mail.
- **Bounded failed logins.** All IMAP logins come from the mail server's own
  IP. Unknown addresses are refused before any IMAP traffic; real failures
  are capped at 3 per account, 5 per client IP and 8 globally per 15 minutes,
  after which sign-in is refused for everyone (fail closed). This guards
  users' passwords against guessing and keeps Dovecot's per-IP login delays
  from slowing the gateway down.
- **No poste.io changes.** poste.io's IP blocking ("guard") is part of its
  SMTP server and IMAP failures don't trigger it, so the gateway needs no
  whitelist. Don't add one: a guard whitelist entry makes SMTP from that IP
  skip spam and virus checks, and does nothing for IMAP.
- **Credentials at rest.** `state/gateway.json` holds sealed passwords and
  token hashes only. Without `secrets/vault_key` the passwords cannot be
  recovered; with it they can, so the key and the state file are as
  sensitive as the passwords themselves.
- **No secrets or mail in logs.** Logs carry addresses, IPs and status codes.
- **A changed poste.io password** makes the next tool call fail; the gateway
  then deletes that grant (so it stops retrying the old password against
  poste.io) and the user reconnects.

## Revoking access

- A user: disconnect the connector in Claude (calls the revocation endpoint).
- An admin: remove the address from `ALLOWED_USERS` and restart; grants for
  addresses no longer allowed are deleted at startup.
- Everyone at once: replace `secrets/vault_key` and delete `state/`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_URL` | required | External URL, e.g. `https://mail.example.com:8443`. OAuth issuer; the MCP endpoint is `PUBLIC_URL/mcp`. |
| `ALLOWED_USERS` | required | Comma-separated mailbox addresses allowed to sign in. |
| `IMAP_HOST` | required | poste.io IMAP host. |
| `IMAP_PORT` | `993` | IMAPS port. |
| `IMAP_SERVERNAME` | `IMAP_HOST` | Name the IMAP certificate is checked against. |
| `VAULT_KEY_FILE` / `VAULT_KEY` | required | 32-byte key, hex or base64. Prefer the file (a Docker secret). |
| `STATE_FILE` | `/state/gateway.json` | Clients and grants. |
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `8080` | Inside the container network only. |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | `3600` / `2592000` | Seconds. |

## Deploying on the mail server

`deploy/` holds the compose project: the gateway plus a Caddy built with the
Cloudflare DNS plugin, because ports 80/443 belong to poste.io and the
certificate has to come via DNS-01. It assumes poste.io runs on the same
host (set `IMAP_HOST_IP` otherwise) and that the zone is on Cloudflare.

All site-specific values (hostnames, port, ACME email, allowed users) go in
`deploy/.env`, which is gitignored; see `deploy/.env.example`.

```bash
# on the mail server, from a copy of this repo
cd poste-mcp-gateway/deploy
install -d -m 700 secrets state caddy-data
(umask 077; openssl rand -hex 32 > secrets/vault_key)
# secrets/cf_token: Cloudflare API token, Zone:DNS:Edit on your zone only (chmod 600)
cp .env.example .env && chmod 600 .env              # fill in your values
docker compose up -d --build
docker compose logs -f
```

Then in Claude: Settings → Connectors → Add custom connector →
`https://<PUBLIC_HOST>:<PUBLIC_PORT>/mcp`.

## Development

```bash
npm ci
npm test          # unit, read-only guarantees, full OAuth + MCP flow (IMAP faked)
npm run lint      # tsc --noEmit
npm run build
```

### Live IMAP tests

`test/live.test.ts` runs the IMAP layer against a real server and is skipped
by default. With Dovecot (the server poste.io uses; also checks that `EXAMINE`
makes the server refuse writes):

```bash
docker run -d --rm --name gw-dovecot -e USER_PASSWORD=dovecot-test -p 127.0.0.1:4993:31993 dovecot/dovecot:2.4.1
LIVE_IMAP=1 LIVE_IMAP_SERVER=dovecot LIVE_IMAP_PORT=4993 LIVE_IMAP_PASSWORD=dovecot-test npx vitest run test/live.test.ts
```

## Credits

`src/vendor/html-to-markdown.ts` is taken from
[nikolausm/imap-mcp-server](https://github.com/nikolausm/imap-mcp-server)
(MIT, see `src/vendor/LICENSE.imap-mcp-server`).
