# Changelog

Capability changes are called out first: a new version can let an assistant
do more with a mailbox, so read this before bumping a pinned image tag.

## 0.3.0

**New capability.**
- Several of your own mailboxes in one connection: the sign-in page takes
  the primary mailbox plus up to two more, each verified by logging in to it
  and required to be on `ALLOWED_USERS`. New `list_accounts` tool; every
  other tool takes an optional `account`. Send permission (`SEND_USERS`) is
  checked per mailbox.

**Upgrade note.** The state file is migrated from version 1 to 2 on first
start (existing connections become single-mailbox connections). Rolling back
to 0.2.0 afterwards would not read it; users would have to reconnect.

## 0.2.0

**New capabilities (opt-in).**
- `mail.modify`: mark read/unread, flag, move, create folders, move to Trash,
  save drafts (new, reply, reply-all, forward). Users tick it at sign-in.
- `mail.send`: send, reply and forward via the mail server's SMTP. Users tick
  it at sign-in, and only addresses in the new `SEND_USERS` can get it
  (empty by default, so nobody can send until configured).

**Protections.**
- Mail goes out directly only to addresses the mailbox has sent to before;
  other messages are saved in Drafts (`SEND_NEW_RECIPIENTS=draft`).
- `SEND_LIMIT_PER_HOUR` (10), 20 recipients per message, sender fixed to the
  signed-in address, copy kept in Sent.
- OAuth clients can only redirect to `ALLOWED_REDIRECT_HOSTS` (claude.ai,
  claude.com) or loopback.
- Login guard reserves attempts before the IMAP call (one in flight per
  account), locks per account+IP, exempts previously successful IPs from the
  global lock, answers every refusal identically; `POST /login` rate limit.
- Scopes re-checked on every request; refresh-token reuse revokes the grant;
  grants end after `MAX_GRANT_AGE_DAYS` (90).
- All sender-written fields returned inside the untrusted block; header
  fields truncated; messages over 25 MB refused before download; 3
  concurrent tool calls per grant.
- Structured JSON audit log; HSTS; GCM tag length pinned; client table evicts
  unused clients instead of filling up.
- CI actions and base images pinned by digest; Dependabot added.

## 0.1.0

Read-only gateway: OAuth 2.1 sign-in with the user's own IMAP credentials,
five read tools.
