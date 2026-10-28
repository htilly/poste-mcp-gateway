/**
 * What a grant lets Claude do. Read is always granted; the other two are
 * opt-in checkboxes on the sign-in page, and tools for a scope the grant
 * lacks are never registered.
 */
export const SCOPES = {
  /** Search and read mail. */
  read: 'mail.read',
  /** Flags, moves, folders, trash and drafts: changes inside the mailbox. */
  modify: 'mail.modify',
  /** Send, reply and forward through the mail server's SMTP. */
  send: 'mail.send',
} as const;

export type Scope = (typeof SCOPES)[keyof typeof SCOPES];

export const ALL_SCOPES: readonly Scope[] = [SCOPES.read, SCOPES.modify, SCOPES.send];

export function isScope(value: string): value is Scope {
  return (ALL_SCOPES as readonly string[]).includes(value);
}
