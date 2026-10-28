# poste-mcp-gateway

An MCP gateway into poste.io mailboxes. A small, invited group of mailbox
owners add `https://mail.example.com/mcp` as a custom connector in Claude,
sign in once with their own poste.io address and password, and Claude can
then work with **their** mailboxes (up to five of their own in one
connection). It also works as a ChatGPT connector. Reading is always allowed; organizing
(flags, moves, Trash, drafts) and sending are separate permissions each
user ticks at sign-in, and sending must also be enabled per address by the
administrator.

What it has to achieve, and why, is in [docs/requirements.md](docs/requirements.md).

## How it works

```
Claude ──HTTPS :443──▶ reverse proxy ──▶ gateway :8080 ──IMAPS/SMTP──▶ poste.io
                       (TLS)             OAuth 2.1 + MCP
```

- **Sign-in is an IMAP login.** The OAuth authorize step shows a login page;
  the gateway checks the address against `ALLOWED_USERS` and then logs in to
  poste.io with what the user typed. Success issues an authorization code.
  There are no gateway accounts and no other way in.
- **Permissions are scopes chosen at sign-in.** `mail.read` always;
  `mail.modify` and `mail.send` only if ticked (send only for addresses in
  `SEND_USERS`). Tools for scopes a grant lacks are never registered, and
  scopes are re-checked against current configuration on every request.
- **Several of your own mailboxes per connection.** The sign-in page takes
  the primary mailbox plus up to two more, and `add_mailbox` adds more later
  without reconnecting (up to five). Each one must be on the allowlist and is
  proven by logging in to it; at sign-in, if any fails, the whole sign-in
  fails.
  Every tool takes an optional `account` (default: the primary); a mailbox
  outside the grant is unreachable.
- **One grant per sign-in and client.** Each mailbox's IMAP password is
  sealed with AES-256-GCM (key from a mounted file, bound to that address)
  and stored with the grant. Tokens are stored hashed. Access tokens live 1 hour in memory;
  refresh tokens rotate on every use, slide 30 days, and grants end after
  90 days regardless. Replaying a rotated refresh token revokes the grant.
- **Every tool call opens a short IMAP session as that user.** Reads use
  `EXAMINE` and `BODY.PEEK`; only the modify and send tools open a mailbox
  read-write. Nothing is mirrored or cached.
- **Stateless MCP over streamable HTTP:** a fresh server per request, so
  nothing is shared between users.

OAuth endpoints (metadata, dynamic client registration, PKCE, token,
revocation) come from the MCP TypeScript SDK's `mcpAuthRouter`; this project
supplies the provider (`src/provider.ts`).

## Tools

| Tool | Scope | Does |
|---|---|---|
| `list_accounts` | read | The mailboxes in this connection, which is the default, and which may send |
| `add_mailbox` | any | A one-time link (10 minutes) where the user signs in to another mailbox to add it |
| `remove_mailbox` | any | Remove an added mailbox (not the primary) and delete its stored password |
| `list_folders` | read | Folders with message and unread counts |
| `search_mail` | read | IMAP SEARCH in one folder (text, from, to, subject, since, before, unseen), newest first, max 50 |
| `read_message` | read | Headers, body as text/Markdown (20k chars max), attachment list |
| `read_thread` | read | Messages in the same conversation (Message-ID / In-Reply-To / References) |
| `read_attachment` | read | Images as images, text formats as text (50k chars), other binaries metadata only; 5 MB max |
| `mark_read`, `flag_messages` | modify | Set or clear `\Seen` / `\Flagged` (max 100 messages per call) |
| `move_messages`, `create_folder` | modify | Move to an existing folder; create a folder |
| `trash_messages` | modify | Move to Trash. Permanent deletion does not exist |
| `save_draft` | modify | New message, reply, reply-all or forward, saved to Drafts |
| `send_message`, `reply_to_message`, `forward_message` | send | Send as the signed-in address via poste.io SMTP, copy kept in Sent |

All tools except `list_accounts`, `add_mailbox` and `remove_mailbox` take an optional `account` (an address
from `list_accounts`). Send permission is checked per mailbox.

Everything a message's sender wrote (subjects, addresses, filenames, bodies,
attachment text) is returned inside `<<<UNTRUSTED EMAIL CONTENT ...>>>`
markers; markers inside the mail are neutralized so a message cannot close
the block early. Images carry an explicit untrusted note.

## Security model

Mail is untrusted input: any message can contain text written to steer an
assistant. The design assumes Claude will sometimes follow such text and
puts the limits in the server:

- **Sending only to known recipients.** Mail goes out directly only to
  addresses this mailbox has sent to before (exact match in Sent). Anything
  else, including forwards and replies to new addresses, is saved in Drafts
  for the user to review and send from their mail client
  (`SEND_NEW_RECIPIENTS=draft`, the default). "Has emailed me" would not
  help: an injected request arrives from exactly the address it wants data
  sent to. Sending is also off unless the address is in `SEND_USERS`,
  capped at `SEND_LIMIT_PER_HOUR` (10) and 20 recipients per message, always
  from the signed-in address, and every send is audit-logged.
- **Contained changes.** Mutating IMAP calls exist only in `mail-write.ts`
  and SMTP only in `smtp.ts`; `test/readonly.test.ts` fails the build
  otherwise, and enforces that read-only grants never see a write tool.
  There is no expunge and no folder deletion or rename.
- **Only known assistants can be clients.** Dynamic client registration
  accepts redirect URIs only for `ALLOWED_REDIRECT_HOSTS` (claude.ai and
  claude.com by default; add chatgpt.com for ChatGPT) or loopback, so nobody
  can register a look-alike client that collects authorization codes
  through the genuine sign-in page. The page still shows the full redirect
  URI.
- **Adding mailboxes later never puts a password in the chat.**
  `add_mailbox` returns a single-use link bound to the connection; the
  password is entered on the gateway's own page. A link without the
  mailbox's password adds nothing, so a prompt-injected request for one is
  harmless.
- **Bounded failed logins, also under parallel requests.** All IMAP logins
  come from one IP. Unknown addresses are refused before any IMAP traffic.
  Each attempt is reserved before the IMAP call, an account has at most one
  attempt in flight, and failures are capped per account+IP (3), per IP
  (5) and globally (8) per 15 minutes; IPs with an earlier successful
  sign-in are exempt from the global lock. Every refusal looks the same, so
  the page reveals neither the allowlist nor lock state. `POST /login` is
  additionally rate-limited per IP.
- **No poste.io changes.** poste.io's IP blocking ("guard") is part of its
  SMTP server and IMAP failures don't trigger it, so the gateway needs no
  whitelist. Don't add one: a guard whitelist entry makes SMTP from that IP
  skip spam and virus checks, and does nothing for IMAP.
- **Credentials at rest.** The state file holds sealed passwords and token
  hashes only. Without the vault key the passwords cannot be recovered;
  with it they can, so keep the key outside the deploy directory where
  possible and treat both as sensitive as the passwords. The sign-in page
  tells users their password is stored.
- **Bounded work.** Messages over 25 MB are refused before download; one
  grant may run at most 3 tool calls at once; header fields are truncated.
- **Audit log.** One JSON line per event on stderr: sign-ins (with scopes
  and client), refused sign-ins, client registrations, grant revocations,
  and every send, held-as-draft, move, trash, flag and draft. Never
  passwords, tokens or message content.
- **A changed poste.io password** makes the next tool call fail; the gateway
  then deletes that grant and the user reconnects.

## Revoking access

- A user: disconnect the connector in Claude (calls the revocation endpoint).
- An admin: remove the address from `ALLOWED_USERS` and restart; grants for
  addresses no longer allowed are deleted at startup. Removing an address
  from `SEND_USERS` takes send away on the next request. An address removed
  from `ALLOWED_USERS` also leaves every connection it was added to; a
  connection whose primary mailbox it was is deleted.
- Everyone at once: replace the vault key and delete the state file.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_URL` | required | External URL, e.g. `https://mail.example.com`. OAuth issuer; the MCP endpoint is `PUBLIC_URL/mcp`. |
| `ALLOWED_USERS` | required | Comma-separated mailbox addresses allowed to sign in. |
| `SEND_USERS` | empty | Addresses that may be granted `mail.send`. Must be a subset of `ALLOWED_USERS`. Empty: nobody can send. |
| `SEND_NEW_RECIPIENTS` | `draft` | `draft`: mail to never-before-mailed recipients is saved to Drafts instead. `allow`: send anyway. |
| `SEND_LIMIT_PER_HOUR` | `10` | Messages per user per hour. |
| `ALLOWED_REDIRECT_HOSTS` | `claude.ai,claude.com` | https hosts OAuth clients may redirect to (subdomains included). Add `chatgpt.com` to allow ChatGPT. Loopback http is always allowed. |
| `MAX_GRANT_AGE_DAYS` | `90` | Absolute grant lifetime; refreshing never extends past it. |
| `IMAP_HOST` | required | poste.io IMAP host. |
| `IMAP_PORT` | `993` | IMAPS port. |
| `IMAP_SERVERNAME` | `IMAP_HOST` | Name the IMAP certificate is checked against. |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURE` | `IMAP_HOST` / `587` / port 465 | Submission server; STARTTLS is required unless `SMTP_SECURE=true`. |
| `VAULT_KEY_FILE` / `VAULT_KEY` | required | 32-byte key, hex or base64. Prefer the file (a read-only mount or Docker secret): an env var shows up in `docker inspect`. |
| `STATE_FILE` | `/state/gateway.json` | Clients and grants. |
| `LISTEN_HOST` / `LISTEN_PORT` | `0.0.0.0` / `8080` | Inside the container; publish it on loopback only. |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | `3600` / `2592000` | Seconds. |

## Connecting

### Claude

Settings → Connectors → **Add custom connector** → URL `https://<host>/mcp`.
Claude opens the sign-in page: enter the primary mailbox and its password,
optionally more mailboxes, tick what else to allow, and **Allow access**.

### ChatGPT

ChatGPT uses the same OAuth flow (dynamic client registration and PKCE),
with its callback on `chatgpt.com`. On the server, allow it first:

```
ALLOWED_REDIRECT_HOSTS=claude.ai,claude.com,chatgpt.com
```

Then in ChatGPT (custom connectors need Developer Mode, which OpenAI limits
to some plans, and the menu names change between releases):

1. Settings → Apps & Connectors → Advanced settings → turn on **Developer
   mode**.
2. Back in Apps & Connectors, **Create** a connector: any name, MCP server
   URL `https://<host>/mcp`, authentication **OAuth**.
3. ChatGPT registers itself and opens the gateway's sign-in page; sign in
   as for Claude.

The sign-in page shows where access goes (`https://chatgpt.com/...`); if it
shows any other host, stop.

### Adding or removing mailboxes later

Ask the assistant to "add a mailbox". It calls `add_mailbox` and gives you a
link; open it yourself, sign in to the mailbox to add, and it is part of the
connection immediately. Never type a mailbox password into the chat.
"Remove <address>" calls `remove_mailbox`.

## Deploying

**Claude only connects to port 443.** claude.ai's connector service does
not reach custom connectors on other ports (verified: requests to `:443`
arrived, requests to `:8443` never left Anthropic). The gateway therefore
has to be served at `https://<host>/mcp` on the standard port. On the
poste.io host itself, 443 belongs to poste.io's nginx, so in practice:

- **Behind an existing reverse proxy (recommended).** Run the image on any
  host that already terminates TLS on 443 (nginx/SWAG, Caddy, Traefik) and
  can reach poste.io on 993. Publish the gateway on `127.0.0.1` only, set
  `PUBLIC_URL=https://<host>` (no port), and proxy `/` to it with
  `X-Forwarded-For` set and response buffering off (MCP streams server-sent
  events). The gateway trusts exactly one proxy hop for the client IP. Use a
  DNS-only record, not a CDN proxy, if the CDN should not see mail content.
- **`deploy/`** (below) runs gateway plus Caddy on the mail server itself, on
  a non-standard port. That works for clients that can use another port, but
  not as a claude.ai connector.

### Example nginx location (SWAG style)

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name mail-mcp.*;
    include /config/nginx/ssl.conf;
    location / {
        include /config/nginx/proxy.conf;   # sets X-Forwarded-For etc.
        proxy_pass http://127.0.0.1:8770;   # gateway published on loopback only
        proxy_buffering off;
    }
}
```

The gateway sets `Strict-Transport-Security` itself when `PUBLIC_URL` is https.

### Standalone on the mail server (`deploy/`)

`deploy/` holds a compose project: the gateway plus a Caddy built with the
Cloudflare DNS plugin, because ports 80/443 belong to poste.io and the
certificate has to come via DNS-01. It assumes poste.io runs on the same
host (set `IMAP_HOST_IP` otherwise) and that the zone is on Cloudflare.
Docker publishes the port past ufw for IPv4 only; for IPv6 the port also
needs a ufw rule (`ufw allow <PUBLIC_PORT>/tcp`).

All site-specific values (hostnames, port, ACME email, allowed users) go in
`deploy/.env`, which is gitignored; see `deploy/.env.example`.

Images are built by GitHub Actions (`.github/workflows/ci.yml`) after the
unit and live-IMAP tests pass, and pushed to GHCR:
`ghcr.io/<owner>/poste-mcp-gateway` and `ghcr.io/<owner>/poste-mcp-gateway-caddy`,
tagged `latest` (main), `sha-xxxxxxx` and the version on `v*` tags. Pin a
version tag in production rather than `latest`, so a capability change
never arrives on an unattended pull (see CHANGELOG.md). The
server only needs `deploy/compose.yaml`, `deploy/caddy/Caddyfile` and the
files below; it never builds anything.

```bash
# on the mail server
mkdir -p poste-mcp-gateway/caddy && cd poste-mcp-gateway
# copy deploy/compose.yaml, deploy/.env.example and deploy/caddy/Caddyfile here
install -d -m 700 secrets state caddy-data
(umask 077; openssl rand -hex 32 > secrets/vault_key)
# secrets/cf_token: Cloudflare API token, Zone:DNS:Edit on your zone only (chmod 600)
cp .env.example .env && chmod 600 .env              # fill in your values
# private package? log in once with a token that has read:packages:
#   docker login ghcr.io -u <user>
docker compose pull && docker compose up -d
docker compose logs -f
```

Upgrade: read CHANGELOG.md, bump the pinned tag, then `docker compose pull && docker compose up -d`.

Then connect a client as described under [Connecting](#connecting). Note
that claude.ai only reaches port 443, so this standalone setup needs a 443
front end for it.

## Development

```bash
npm ci
npm test          # unit, write confinement, send policy, full OAuth + MCP flow (IMAP faked)
npm run lint      # tsc --noEmit
npm run build
```

### Live IMAP tests

`test/live.test.ts` runs the IMAP layer against a real server and is skipped
by default. With Dovecot (the server poste.io uses; also checks that `EXAMINE`
makes the server refuse writes, the write tools, and exact Sent-history matching):

```bash
docker run -d --rm --name gw-dovecot -e USER_PASSWORD=dovecot-test -p 127.0.0.1:4993:31993 dovecot/dovecot:2.4.1
LIVE_IMAP=1 LIVE_IMAP_SERVER=dovecot LIVE_IMAP_PORT=4993 LIVE_IMAP_PASSWORD=dovecot-test npx vitest run test/live.test.ts
```

## Credits

`src/vendor/html-to-markdown.ts` is taken from
[nikolausm/imap-mcp-server](https://github.com/nikolausm/imap-mcp-server)
(MIT, see `src/vendor/LICENSE.imap-mcp-server`).
