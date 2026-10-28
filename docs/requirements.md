# poste-mcp-gateway: requirements

## Goal

Give a small, invited set of poste.io mailbox owners (for example a family
sharing one self-hosted mail server) a way to let Claude read their own mail. Each person adds the gateway as a
custom MCP connector in Claude (claude.ai, Claude Desktop, mobile), signs in
once with their normal poste.io address and password, and from then on Claude
can search and read that person's mailbox — and only that mailbox — but never
change it.

## Users and access

- **R1. Who can sign in.** Only addresses on an explicit allowlist
  (`ALLOWED_USERS`). There is no open sign-up and no separate gateway account.
- **R2. Identity is the mailbox.** A user proves who they are by logging in
  to poste.io over IMAP with their own credentials. A successful IMAP login is
  the only way to obtain access.
- **R3. Isolation between users.** A user can only ever reach the mailbox they
  signed in with. Nothing in a request can select another user's mailbox.
- **R4. Revocation.** A user (or the admin) can revoke access; revoking deletes
  the stored credential. A changed poste.io password invalidates access, and
  the user must sign in again.

## What Claude can do

- **R5. Read-only, structurally.** The gateway can list folders, search,
  read messages and threads, and read attachments. It cannot send, reply,
  forward, draft, move, delete, flag, mark read/unread or create folders.
  This is guaranteed by the code containing no such operations, not by a
  configuration flag. Mailboxes are opened with IMAP `EXAMINE` (read-only on
  the server side too) and messages are fetched with `BODY.PEEK`, so reading
  does not mark mail as seen.
- **R6. Mail is untrusted input.** Email content can contain text written to
  look like instructions. Every body and attachment the gateway returns is
  marked as untrusted data. Because nothing can be changed or sent, a
  malicious email that reaches Claude can only be read.
- **R7. Bounded output.** Bodies and attachments are size-capped so a single
  message cannot flood Claude's context.

## How it connects

- **R8. Custom connector.** Reachable at `https://<host>/mcp` on port 443,
  because claude.ai does not connect to custom connectors on other ports.
  MCP streamable HTTP, usable as a claude.ai custom connector: OAuth 2.1
  with PKCE, dynamic client registration, and the RFC 9728 / RFC 8414
  metadata documents.
- **R9. TLS.** Valid public certificate for the mail host's name, obtained without
  touching ports 80/443 (those belong to poste.io): DNS-01 via Cloudflare.

## Relationship to poste.io

- **R10. Runs beside poste.io, disconnected from it.** Its own containers,
  compose project and bridge network. No shared volumes, no access to
  poste.io's data directory or configuration, no host networking. It talks to
  poste.io only as an ordinary IMAP client over IMAPS (993) with certificate
  verification.
- **R11. Bounded failed logins, no poste.io changes.** All IMAP logins come
  from the mail server's own IP. The gateway must never forward unbounded
  failed logins: unknown addresses are rejected before any IMAP traffic, and
  failed logins are limited per account, per client IP and globally (fail
  closed). This protects users' passwords from guessing and keeps Dovecot's
  per-IP login delays (`auth_failure_delay`, growing after repeated failures)
  from slowing the gateway down.
  poste.io's IP blocking ("guard") lives in its SMTP server (Haraka) and is
  not triggered by IMAP failures, so no poste.io whitelist is needed. One must
  not be added: a guard whitelist entry makes SMTP from that IP skip SPF,
  DKIM, rspamd and ClamAV, and does nothing for IMAP.
- **R12. Unaffected by mail updates.** The poste.io auto-update script only
  manages `/config`; the gateway lives in its own directory and is never
  pulled or restarted by it.

## Security

- **R13. Credentials at rest.** Each user's IMAP password is stored only
  sealed with AES-256-GCM under a key held in a Docker secret, bound to that
  user. OAuth tokens are stored only as hashes.
- **R14. No secrets or mail in logs.** Logs carry identifiers (user, folder,
  UID, client), never passwords, tokens or message content.
- **R15. No telemetry.** The only outbound connections are to poste.io (IMAP)
  and, for Caddy, Let's Encrypt and the Cloudflare DNS API.
- **R16. Hardened containers.** Non-root, read-only root filesystem, all
  capabilities dropped, `no-new-privileges`, memory and PID limits, rotated
  logs. Only port 8443 is published.

## Out of scope (for now)

- Sending or changing mail in any form.
- Users outside the allowlist, self-service sign-up, other mail providers.
- Passkeys. Planned as a later step: after the first IMAP sign-in, a user can
  register a passkey and use it for later authorizations.
- Full-text search beyond what IMAP `SEARCH` provides (no local index or
  mirror of mail).

## Acceptance

- An allowlisted user adds `https://<mail host>:8443/mcp` in Claude, signs
  in with their poste.io credentials, and Claude can search and read their
  mail.
- A non-allowlisted address, or a wrong password, is refused, and repeated
  attempts never cause more than the configured number of IMAP login failures.
- No tool call can change a mailbox: verified by tests asserting the tool list
  and by the absence of mutating IMAP calls in the source.
- Two users signed in at once only ever see their own mail.
