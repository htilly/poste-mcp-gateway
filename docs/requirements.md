# poste-mcp-gateway: requirements

## Goal

Give a small, invited set of poste.io mailbox owners (for example a family
sharing one self-hosted mail server) a way to let Claude work with their own
mail. Each person adds the gateway as a custom MCP connector in Claude
(claude.ai, Claude Desktop, mobile), signs in once with their normal
poste.io address and password, and from then on Claude can search and read
that person's mailbox, and only that mailbox. Organizing and sending are
opt-in, per person, and bounded by the server rather than by Claude's
judgment.

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
  the user must sign in again. Grants end after a maximum age, and a replayed
  refresh token revokes its grant.
- **R5. Only Claude as client.** OAuth clients may only redirect to the
  configured Claude hosts or loopback, so the genuine sign-in page cannot be
  used to hand an authorization code to anyone else.

## What Claude can do

- **R6. Three permissions, chosen at sign-in.** `mail.read` (always): list
  folders, search, read messages, threads and attachments. `mail.modify`
  (opt-in): mark read/unread, flag, move, create folders, move to Trash,
  save drafts. `mail.send` (opt-in, and only for addresses the administrator
  lists in `SEND_USERS`): send, reply and forward. Tools for a permission a
  grant lacks are not offered at all, and permissions are re-checked against
  current configuration on every request.
- **R7. Reading changes nothing.** Read tools open mailboxes with IMAP
  `EXAMINE` and fetch with `BODY.PEEK`, so reading never marks mail as seen.
- **R8. No irreversible changes.** There is no permanent deletion (expunge),
  no folder deletion or rename, and no choice of sender address.
- **R9. Mail is untrusted input.** Email content can contain text written to
  look like instructions. Everything a sender wrote (bodies, subjects,
  addresses, filenames, attachments) is returned marked as untrusted data.
  Because Claude may still follow such text, the limits on what it can do
  are enforced by the server (R10), not by the marking.
- **R10. Sending is bounded by the server.** Mail is sent directly only to
  addresses the mailbox has sent to before; a message with any new recipient
  is saved in Drafts for the user to send themselves. Sending is capped per
  hour and per message, always from the signed-in address, with a copy in
  Sent, and every send is logged.
- **R11. Bounded output and work.** Bodies and attachments are size-capped,
  oversized messages are refused before download, and concurrent requests
  per user are limited.

## How it connects

- **R12. Custom connector.** Reachable at `https://<host>/mcp` on port 443,
  because claude.ai does not connect to custom connectors on other ports.
  MCP streamable HTTP with OAuth 2.1, PKCE, dynamic client registration, and
  the RFC 9728 / RFC 8414 metadata documents.
- **R13. TLS end to end on own infrastructure.** TLS terminates at a reverse
  proxy the operator controls, with a DNS-only record, so no CDN sees mail
  content. HSTS is sent.

## Relationship to poste.io

- **R14. Separate from poste.io.** The gateway is its own container with no
  access to poste.io's data directory or configuration. It talks to poste.io
  only as an ordinary client: IMAPS (993) and, for sending, SMTP submission,
  both with certificate verification. poste.io's own update process never
  touches it.
- **R15. Bounded failed logins, no poste.io changes.** The gateway must never
  forward unbounded failed logins, including under parallel requests:
  unknown addresses are rejected before any IMAP traffic, each attempt is
  reserved before the IMAP call, and failures are limited per account+IP,
  per IP and globally (fail closed, with IPs that signed in before exempt
  from the global lock). Every refusal looks the same. poste.io's IP
  blocking ("guard") lives in its SMTP server and is not triggered by IMAP
  failures, so no poste.io whitelist is needed, and one must not be added:
  it would make SMTP from that IP skip spam and virus checks.

## Security

- **R16. Credentials at rest.** Each user's IMAP password is stored only
  sealed with AES-256-GCM (full 16-byte tags) under a key held outside the
  environment (mounted file), bound to that user. OAuth tokens are stored
  only as hashes. The sign-in page tells users their password is stored.
- **R17. Audit, without secrets or mail.** A structured log records
  sign-ins, refusals, registrations, revocations and every change or send,
  with identifiers only, never passwords, tokens or message content. User
  input cannot forge log lines.
- **R18. No telemetry.** The only outbound connections are to poste.io.
- **R19. Hardened container and supply chain.** Non-root, read-only root
  filesystem, all capabilities dropped, `no-new-privileges`, memory and PID
  limits, rotated logs, published on loopback only. CI actions and base
  images are pinned by digest; production pins a release tag.

## Out of scope (for now)

- Users outside the allowlist, self-service sign-up, other mail providers.
- Passkeys. Planned as a later step: after the first IMAP sign-in, a user can
  register a passkey and use it for later authorizations.
- Several mailboxes in one connection (planned next).
- Full-text search beyond what IMAP `SEARCH` provides (no local index or
  mirror of mail).

## Acceptance

- An allowlisted user adds `https://<host>/mcp` in Claude, signs in with
  their poste.io credentials, and Claude can search and read their mail.
- A non-allowlisted address, or a wrong password, is refused, and repeated
  or parallel attempts never cause more than the configured number of IMAP
  login failures.
- A read-only grant is offered no tool that changes or sends anything, and
  mutating IMAP and SMTP code lives only in `mail-write.ts` and `smtp.ts`:
  enforced by tests.
- A request to send or forward to an address the mailbox has never mailed
  ends up in Drafts, not in the recipient's inbox.
- Two users signed in at once only ever see their own mail.
