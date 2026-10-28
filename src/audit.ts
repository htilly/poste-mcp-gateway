/**
 * Structured audit log: one JSON object per line on stderr. JSON encoding
 * means user-supplied values (an address typed into the sign-in form) can
 * never forge or split log lines. Identifiers only: never passwords, tokens
 * or message content.
 */
export type AuditFields = Record<string, string | number | boolean | string[] | undefined>;

export type Audit = (event: string, fields: AuditFields) => void;

export const audit: Audit = (event, fields) => {
  process.stderr.write(JSON.stringify({ ts: new Date().toISOString(), event, ...fields }) + '\n');
};

/** For tests and callers that do not want logging. */
export const silentAudit: Audit = () => {};
