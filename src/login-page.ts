import { createHash } from 'node:crypto';
import { SCOPES, type Scope } from './scopes.js';

export interface LoginView {
  pendingId: string;
  clientName: string;
  /** Where the authorization code goes. Shown in full: it is the real identity of the client. */
  redirectUri: string;
  message?: string;
  /** Scopes ticked on a previous attempt, so a retry keeps the choice. */
  requested?: Scope[];
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/**
 * Checking the password against the mail server takes a few seconds. Without
 * feedback people click again, the browser aborts the first request, and with
 * it the redirect that carries the authorization code. This disables the
 * button after the first submit and swallows any further submits.
 */
const SUBMIT_ONCE_SCRIPT =
  "var f=document.querySelector('form');if(f)f.addEventListener('submit',function(e){" +
  "var b=this.querySelector('button');" +
  "if(b.disabled){e.preventDefault();return;}" +
  "b.disabled=true;b.textContent='Checking with the mail server\\u2026';});";

const SCRIPT_HASH = createHash('sha256').update(SUBMIT_ONCE_SCRIPT).digest('base64');

/**
 * The pages' CSP: no script runs except the one above, pinned by hash.
 *
 * form-action also governs where a form submission may be redirected
 * (Chrome enforces this), and a successful sign-in answers with a redirect
 * to the OAuth client's callback. So the sign-in page allows exactly that
 * callback's origin, which registration already limited to allowed hosts;
 * every other page allows only itself.
 */
export function pageCsp(redirectUri?: string): string {
  let formAction = "'self'";
  if (redirectUri) {
    const origin = new URL(redirectUri).origin;
    if (/^https?:\/\/[a-z0-9.:\-\[\]]+$/i.test(origin)) formAction += ` ${origin}`;
  }
  return [
    "default-src 'none'",
    "style-src 'unsafe-inline'",
    `script-src 'sha256-${SCRIPT_HASH}'`,
    `form-action ${formAction}`,
    "frame-ancestors 'none'",
    "base-uri 'none'",
  ].join('; ');
}

/**
 * The only page this service serves. Names the client and where it will
 * redirect, because dynamic registration lets anyone register a client and
 * the user is the one deciding whether to trust it.
 */
const STYLE = `<style>
  :root { color-scheme: light dark; --fg: #1a1a1a; --bg: #f6f6f4; --card: #fff; --muted: #666; --accent: #2b5fd9; --err: #b3261e; }
  @media (prefers-color-scheme: dark) { :root { --fg: #eee; --bg: #151515; --card: #1f1f1f; --muted: #aaa; --accent: #7aa2ff; --err: #ff8a80; } }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--fg);
         font: 16px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; }
  main { width: min(26rem, calc(100% - 2rem)); background: var(--card); border-radius: 12px; padding: 1.75rem; box-shadow: 0 1px 4px #0002; }
  h1 { font-size: 1.25rem; margin: 0 0 .5rem; }
  p { margin: .25rem 0 1rem; color: var(--muted); }
  label { display: block; margin: .75rem 0 .25rem; font-weight: 600; }
  input { box-sizing: border-box; width: 100%; padding: .6rem .7rem; font: inherit; border: 1px solid #8886; border-radius: 8px; background: transparent; color: inherit; }
  button { margin-top: 1.25rem; width: 100%; padding: .7rem; font: inherit; font-weight: 600; border: 0; border-radius: 8px; background: var(--accent); color: #fff; cursor: pointer; }
  button:disabled { opacity: .6; cursor: progress; }
  details { margin: 1rem 0 0; }
  summary { cursor: pointer; font-weight: 600; }
  fieldset { border: 1px solid #8884; border-radius: 8px; margin: 1rem 0 0; padding: .5rem .8rem .7rem; }
  legend { font-weight: 600; padding: 0 .3rem; }
  .opt { display: flex; gap: .6rem; align-items: flex-start; margin: .5rem 0 0; font-weight: 400; }
  .opt input { width: auto; margin-top: .3rem; }
  .opt small { display: block; color: var(--muted); }
  .error { color: var(--err); }
  .note { font-size: .85rem; }
  code { font-size: .8rem; word-break: break-all; }
</style>`;

/** The shell every gateway page shares: same styles, same hash-pinned script, nothing else. */
function page(title: string, main: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
${STYLE}
</head>
<body>
${main}
<script>${SUBMIT_ONCE_SCRIPT}</script>
</body>
</html>`;
}

export function renderLoginPage(view: LoginView): string {
  const message = view.message ? `<p class="error" role="alert">${escapeHtml(view.message)}</p>` : '';
  const checked = (scope: Scope) => (view.requested?.includes(scope) ? ' checked' : '');
  return page('Sign in to mail', `<main>
  <h1>Sign in to your mailbox</h1>
  <p><strong>${escapeHtml(view.clientName)}</strong> is asking to access your mail. Access is always <strong>read</strong>; anything more only if you tick it below.</p>
  <p class="note">Access goes to <code>${escapeHtml(view.redirectUri)}</code>. The client name above is chosen by the client itself and not verified; only continue if you just connected this server in Claude yourself.</p>
  ${message}
  <form method="post" action="/login" autocomplete="on">
    <input type="hidden" name="pending" value="${escapeHtml(view.pendingId)}">
    <label for="user">Email address</label>
    <input id="user" name="user" type="email" autocomplete="username" required autofocus>
    <label for="password">Mail password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <details>
      <summary>Add more of your mailboxes (optional)</summary>
      <p class="note">Each one is checked by signing in to it, so only mailboxes you have the password for can be added.</p>
      ${[2, 3]
        .map(
          n => `<label for="user${n}">Mailbox ${n}</label>
      <input id="user${n}" name="user" type="email" autocomplete="off">
      <label for="password${n}">Password for mailbox ${n}</label>
      <input id="password${n}" name="password" type="password" autocomplete="off">`,
        )
        .join('\n      ')}
    </details>
    <fieldset>
      <legend>Also allow</legend>
      <label class="opt"><input type="checkbox" name="scope" value="${SCOPES.modify}"${checked(SCOPES.modify)}>
        <span>Organize, delete and drafts<small>Mark read/unread, flag, move, create folders, move to Trash, save drafts.</small></span></label>
      <label class="opt"><input type="checkbox" name="scope" value="${SCOPES.send}"${checked(SCOPES.send)}>
        <span>Send mail as you<small>Send, reply and forward. Only for addresses the administrator allows to send.</small></span></label>
    </fieldset>
    <button type="submit">Allow access</button>
  </form>
  <p class="note">Only invited addresses can sign in. Your mail password is stored encrypted on this server so the assistant can reach your mailbox; disconnecting the connector deletes it.</p>
</main>`);
}

export interface AddMailboxView {
  token: string;
  /** Mailboxes already in the connection, primary first. */
  accounts: string[];
  message?: string;
  /** Set after success: shows the confirmation instead of the form. */
  added?: string;
}

/**
 * The page behind an add_mailbox link: proves one more mailbox with its own
 * password and attaches it to an existing connection, so Claude never sees
 * the password and the connector does not have to be reconnected.
 */
export function renderAddMailboxPage(view: AddMailboxView): string {
  const list = view.accounts.map(a => `<li><code>${escapeHtml(a)}</code></li>`).join('');
  if (view.added) {
    return page(
      'Mailbox added',
      `<main>
  <h1>Mailbox added</h1>
  <p><code>${escapeHtml(view.added)}</code> is now part of this connection. You can close this page and go back to Claude.</p>
  <p class="note">Mailboxes in this connection:</p>
  <ul>${list}</ul>
</main>`,
    );
  }
  const message = view.message ? `<p class="error" role="alert">${escapeHtml(view.message)}</p>` : '';
  return page(
    'Add a mailbox',
    `<main>
  <h1>Add a mailbox to your connection</h1>
  <p>This connection currently has:</p>
  <ul>${list}</ul>
  <p>Sign in to the mailbox you want to add. Only invited addresses can be added, and only with their own password.</p>
  ${message}
  <form method="post" action="/add-mailbox" autocomplete="off">
    <input type="hidden" name="t" value="${escapeHtml(view.token)}">
    <label for="user">Email address</label>
    <input id="user" name="user" type="email" required autofocus>
    <label for="password">Mail password</label>
    <input id="password" name="password" type="password" required>
    <button type="submit">Add mailbox</button>
  </form>
  <p class="note">This link works once and expires 10 minutes after it was created. The password is stored encrypted on this server, like the others in this connection.</p>
</main>`,
  );
}
