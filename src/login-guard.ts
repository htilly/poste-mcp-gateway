/**
 * Decides whether a sign-in attempt may reach the mail server at all.
 *
 * Every IMAP login this gateway makes comes from one IP, so failed logins it
 * forwards earn that IP Dovecot's growing login delays, which then slow every
 * user of the gateway. A stranger hammering the sign-in page must therefore
 * never translate into IMAP failures, and the limits must hold for parallel
 * requests too, not just sequential ones.
 *
 *  1. Allowlist: an address not on ALLOWED_USERS is rejected without any IMAP
 *     traffic, with the same answer as a wrong password or a lock.
 *  2. Attempts are reserved before the IMAP call (check) and settled after it
 *     (record / release). In-flight attempts count against every limit, and an
 *     account has at most one attempt in flight, so a burst of parallel
 *     requests cannot all pass the check before the first failure lands.
 *  3. Failure windows per account+IP pair and per IP. Locking the pair rather
 *     than the account means a stranger cannot lock a user out from their own
 *     network.
 *  4. A global failure budget. Once spent, no IMAP login is attempted, except
 *     from IPs that have signed in successfully before.
 */

export interface GuardLimits {
  windowMs: number;
  perPair: number;
  perIp: number;
  global: number;
  /** How long a successful sign-in exempts its IP from the global lock. */
  trustedIpMs: number;
}

export const DEFAULT_LIMITS: GuardLimits = {
  windowMs: 15 * 60 * 1000,
  perPair: 3,
  perIp: 5,
  global: 8,
  trustedIpMs: 30 * 24 * 3600 * 1000,
};

export type GuardDecision = { ok: true } | { ok: false; reason: 'not_allowed' | 'busy' | 'locked' };

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

class Counter {
  private readonly n = new Map<string, number>();
  get(key: string): number {
    return this.n.get(key) ?? 0;
  }
  inc(key: string): void {
    this.n.set(key, this.get(key) + 1);
  }
  dec(key: string): void {
    const v = this.get(key) - 1;
    if (v > 0) this.n.set(key, v);
    else this.n.delete(key);
  }
}

const GLOBAL = '*';
const pairKey = (account: string, ip: string) => `${account}\n${ip}`;

export class LoginGuard {
  private readonly pairFailures: FailureWindow;
  private readonly ipFailures: FailureWindow;
  private readonly globalFailures: FailureWindow;
  private readonly inFlight = new Counter();
  private readonly trustedIps = new Map<string, number>();

  constructor(
    private readonly allowed: Set<string>,
    private readonly limits: GuardLimits = DEFAULT_LIMITS,
    private readonly now: () => number = Date.now,
  ) {
    this.pairFailures = new FailureWindow(limits.windowMs);
    this.ipFailures = new FailureWindow(limits.windowMs);
    this.globalFailures = new FailureWindow(limits.windowMs);
  }

  static normalize(user: string): string {
    return user.trim().toLowerCase();
  }

  private isTrusted(ip: string, now: number): boolean {
    const at = this.trustedIps.get(ip);
    if (at === undefined) return false;
    if (now - at < this.limits.trustedIpMs) return true;
    this.trustedIps.delete(ip);
    return false;
  }

  /**
   * Call before any IMAP attempt. `ok` reserves an in-flight slot that the
   * caller must settle with record() or release(); anything else must not be
   * followed by an IMAP attempt.
   */
  check(user: string, ip: string): GuardDecision {
    const now = this.now();
    const account = LoginGuard.normalize(user);
    const pair = pairKey(account, ip);
    const used = (w: FailureWindow, key: string, flight: string) => w.count(key, now) + this.inFlight.get(flight);

    if (used(this.ipFailures, ip, `ip:${ip}`) >= this.limits.perIp) return { ok: false, reason: 'locked' };
    if (!this.allowed.has(account)) {
      // Counts against the IP, never against the global IMAP budget: no IMAP traffic happened.
      this.ipFailures.add(ip, now);
      return { ok: false, reason: 'not_allowed' };
    }
    if (this.inFlight.get(`acct:${account}`) > 0) return { ok: false, reason: 'busy' };
    if (used(this.pairFailures, pair, `pair:${pair}`) >= this.limits.perPair) return { ok: false, reason: 'locked' };
    if (!this.isTrusted(ip, now) && used(this.globalFailures, GLOBAL, 'global') >= this.limits.global) {
      return { ok: false, reason: 'locked' };
    }

    for (const key of [`acct:${account}`, `pair:${pair}`, `ip:${ip}`, 'global']) this.inFlight.inc(key);
    return { ok: true };
  }

  private settle(account: string, ip: string): void {
    for (const key of [`acct:${account}`, `pair:${pairKey(account, ip)}`, `ip:${ip}`, 'global']) this.inFlight.dec(key);
  }

  /** Settle a reserved attempt with the IMAP outcome. */
  record(user: string, ip: string, success: boolean): void {
    const account = LoginGuard.normalize(user);
    const now = this.now();
    this.settle(account, ip);
    if (success) {
      this.pairFailures.clear(pairKey(account, ip));
      this.trustedIps.set(ip, now);
      return;
    }
    this.pairFailures.add(pairKey(account, ip), now);
    this.ipFailures.add(ip, now);
    this.globalFailures.add(GLOBAL, now);
  }

  /** Settle a reserved attempt that never reached a verdict (mail server unavailable). */
  release(user: string, ip: string): void {
    this.settle(LoginGuard.normalize(user), ip);
  }
}
