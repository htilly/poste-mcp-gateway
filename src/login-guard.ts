/**
 * Decides whether a sign-in attempt may reach poste.io at all.
 *
 * Every IMAP login this gateway makes comes from the mail server's own IP,
 * so failed logins it forwards earn that IP Dovecot's growing login delays,
 * which then slow every user of the gateway. (poste.io's IP blocking is
 * SMTP-only and is not triggered by IMAP.) A stranger hammering the sign-in
 * page must therefore never translate into IMAP failures. Three layers:
 *
 *  1. Allowlist: an address not on ALLOWED_USERS is rejected without any IMAP
 *     traffic, with the same message as a wrong password.
 *  2. Per-account and per-IP failure windows.
 *  3. A global failure budget. Once spent, no IMAP login is attempted for
 *     anyone until the window rolls over: fail closed.
 */

export interface GuardLimits {
  windowMs: number;
  perAccount: number;
  perIp: number;
  global: number;
}

export const DEFAULT_LIMITS: GuardLimits = {
  windowMs: 15 * 60 * 1000,
  perAccount: 3,
  perIp: 5,
  global: 8,
};

export type GuardDecision =
  | { ok: true }
  | { ok: false; reason: 'not_allowed' | 'account_locked' | 'ip_locked' | 'global_locked' };

class FailureWindow {
  private readonly hits = new Map<string, number[]>();

  constructor(private readonly windowMs: number) {}

  count(key: string, now: number): number {
    const fresh = (this.hits.get(key) ?? []).filter(t => now - t < this.windowMs);
    if (fresh.length) this.hits.set(key, fresh);
    else this.hits.delete(key);
    return fresh.length;
  }

  add(key: string, now: number): void {
    const list = this.hits.get(key) ?? [];
    list.push(now);
    this.hits.set(key, list);
  }

  clear(key: string): void {
    this.hits.delete(key);
  }
}

const GLOBAL = '*';

export class LoginGuard {
  private readonly accounts: FailureWindow;
  private readonly ips: FailureWindow;
  private readonly global: FailureWindow;

  constructor(
    private readonly allowed: Set<string>,
    private readonly limits: GuardLimits = DEFAULT_LIMITS,
    private readonly now: () => number = Date.now,
  ) {
    this.accounts = new FailureWindow(limits.windowMs);
    this.ips = new FailureWindow(limits.windowMs);
    this.global = new FailureWindow(limits.windowMs);
  }

  static normalize(user: string): string {
    return user.trim().toLowerCase();
  }

  /** Call before any IMAP attempt. A `false` here must not be followed by one. */
  check(user: string, ip: string): GuardDecision {
    const now = this.now();
    if (this.global.count(GLOBAL, now) >= this.limits.global) return { ok: false, reason: 'global_locked' };
    if (this.ips.count(ip, now) >= this.limits.perIp) return { ok: false, reason: 'ip_locked' };
    const account = LoginGuard.normalize(user);
    if (!this.allowed.has(account)) {
      // Counts against the IP, never against the global IMAP budget: no IMAP traffic happened.
      this.ips.add(ip, now);
      return { ok: false, reason: 'not_allowed' };
    }
    if (this.accounts.count(account, now) >= this.limits.perAccount) return { ok: false, reason: 'account_locked' };
    return { ok: true };
  }

  /** Record the outcome of an IMAP login that was actually attempted. */
  record(user: string, ip: string, success: boolean): void {
    const account = LoginGuard.normalize(user);
    if (success) {
      this.accounts.clear(account);
      return;
    }
    const now = this.now();
    this.accounts.add(account, now);
    this.ips.add(ip, now);
    this.global.add(GLOBAL, now);
  }
}
