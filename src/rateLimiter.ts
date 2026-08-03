// src/rateLimiter.ts
//
// Atomic brute-force limiter (GHSA-vp89-22wm-gjr8, GHSA-q9vh-jccv-9p23).
//
// This replaces the KV counter that /api/login, /api/register and the 2FA verify
// paths used to share. KV cannot implement a limiter correctly:
//
//   1. The read and the write are separate operations, so N requests dispatched
//      together all `get()` the same count, all compute count+1, and all
//      `put()` it. N guesses advance the counter by one.
//   2. KV is eventually consistent — a `put` takes seconds to propagate and
//      reads at another PoP can be stale for up to ~60s, so even serialised
//      attempts from different edge locations saw a pre-increment count.
//
// A Durable Object fixes both: execution is single-threaded per instance and its
// storage is strongly consistent. Input gates hold incoming events while a
// storage operation is in flight, so the read-modify-write inside `fail()` is
// atomic without any explicit locking.
//
// Each limiter subject — one IP, one account — gets its own instance keyed by
// `idFromName(subject)`. That is deliberate: a single shared instance would
// funnel every login in the world through one thread, which is the documented
// Durable Objects anti-pattern.

import { DurableObject } from 'cloudflare:workers';
import { Env } from './types.js';

/** Failures tolerated before the subject is locked out. */
export const FAILURE_THRESHOLD = 5;
/** Lockout applied at the threshold. Doubles for each failure beyond it. */
export const BASE_LOCKOUT_MS = 15 * 60 * 1000;
/** Ceiling on the exponential backoff, so a lockout is never permanent. */
export const MAX_LOCKOUT_MS = 24 * 60 * 60 * 1000;
/**
 * Idle time after which a subject is forgiven and starts from zero failures.
 * Without this the backoff is cumulative for life, and someone who fat-fingers
 * their password twice a month eventually earns a 24-hour lockout.
 */
export const DECAY_MS = 60 * 60 * 1000;

export interface RateLimitVerdict {
    allowed: boolean;
    /** Seconds until the next attempt is permitted. 0 when allowed. */
    retryAfter: number;
    /** Consecutive failures recorded against this subject. */
    failures: number;
}

/**
 * Per-scope tuning, supplied by the caller rather than baked into the object, so
 * one Durable Object class serves every limit in the app.
 *
 * Credential endpoints want a tight threshold; a volume limit on something
 * harmless (`/api/auth/params`) wants a loose one, or it breaks the first office
 * behind a shared NAT egress.
 */
export interface LimitPolicy {
    threshold: number;
    baseLockoutMs: number;
}

export const CREDENTIAL_POLICY: LimitPolicy = {
    threshold: FAILURE_THRESHOLD,
    baseLockoutMs: BASE_LOCKOUT_MS
};

/** Volume cap for /api/auth/params — matches the 30-per-15-minutes it replaces. */
export const VOLUME_POLICY: LimitPolicy = {
    threshold: 30,
    baseLockoutMs: 15 * 60 * 1000
};

interface LimiterState {
    failures: number;
    /** Epoch ms. 0 means "not locked out". */
    lockedUntil: number;
    updatedAt: number;
}

const STATE_KEY = 'state';

/**
 * Exponential backoff past the threshold: 15m, 30m, 1h, 2h … capped at 24h.
 *
 * The first lockout deliberately matches the flat 15-minute window the old KV
 * limiter advertised, so this is strictly stricter than what it replaces rather
 * than a different trade-off.
 */
export function lockoutFor(failures: number, policy: LimitPolicy = CREDENTIAL_POLICY): number {
    if (failures < policy.threshold) return 0;
    // Clamped before the shift: 2 ** 1024 is Infinity, and Infinity * 0 is NaN.
    const steps = Math.min(failures - policy.threshold, 32);
    return Math.min(policy.baseLockoutMs * 2 ** steps, MAX_LOCKOUT_MS);
}

function verdict(state: LimiterState, now: number): RateLimitVerdict {
    const remaining = state.lockedUntil - now;
    return remaining > 0
        ? { allowed: false, retryAfter: Math.ceil(remaining / 1000), failures: state.failures }
        : { allowed: true, retryAfter: 0, failures: state.failures };
}

export class RateLimiter extends DurableObject<Env> {
    private async load(now: number): Promise<LimiterState> {
        const stored = await this.ctx.storage.get<LimiterState>(STATE_KEY);
        if (!stored) return { failures: 0, lockedUntil: 0, updatedAt: now };
        // Only decay once any active lockout has expired — otherwise a long
        // lockout would forgive itself the moment DECAY_MS elapsed.
        if (now >= stored.lockedUntil && now - stored.updatedAt > DECAY_MS) {
            return { failures: 0, lockedUntil: 0, updatedAt: now };
        }
        return stored;
    }

    /** Read-only: is this subject currently locked out? */
    async peek(): Promise<RateLimitVerdict> {
        const now = Date.now();
        return verdict(await this.load(now), now);
    }

    /**
     * Records one failure and returns the resulting verdict.
     *
     * The load → increment → store sequence is the whole point of this class.
     * Durable Object input gates hold other events while a storage operation is
     * in flight, so concurrent callers are serialised here and each one sees the
     * previous increment — the guarantee KV could not provide.
     */
    async fail(policy: LimitPolicy = CREDENTIAL_POLICY): Promise<RateLimitVerdict> {
        const now = Date.now();
        const previous = await this.load(now);
        const failures = previous.failures + 1;
        const lockout = lockoutFor(failures, policy);
        const next: LimiterState = {
            failures,
            lockedUntil: lockout > 0 ? now + lockout : 0,
            updatedAt: now
        };
        await this.ctx.storage.put(STATE_KEY, next);
        // A Durable Object with empty storage ceases to exist, so scheduling the
        // wipe for the end of the decay window means idle subjects cost nothing
        // and leave nothing behind.
        await this.ctx.storage.setAlarm(Math.max(next.lockedUntil, now) + DECAY_MS);
        return verdict(next, now);
    }

    /** Clears the subject after a genuine success. */
    async reset(): Promise<void> {
        await this.ctx.storage.deleteAlarm();
        await this.ctx.storage.deleteAll();
    }

    async alarm(): Promise<void> {
        await this.ctx.storage.deleteAll();
    }
}

// ─── worker-side helpers ────────────────────────────────────────────────────
//
// Handlers pass a list of subjects rather than one, because a limit must hold
// per account *and* per source IP (GHSA-vp89-22wm-gjr8): an IP-only cap is
// sidestepped by a distributed attacker, and it lets one abuser lock out
// everyone behind a shared NAT egress.

function stub(env: Env, subject: string) {
    return env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(subject));
}

/** `ip` is null for requests without CF-Connecting-IP (local dev, some tests). */
export function ipSubject(scope: string, ip: string | null): string {
    return `${scope}:ip:${ip ?? 'unknown'}`;
}

export function accountSubject(scope: string, account: string | number): string {
    return `${scope}:account:${account}`;
}

/**
 * The strictest verdict wins: any blocked subject blocks the request, and
 * between two blocked subjects the longer lockout is the one reported.
 *
 * `failures` is the highest count across the subjects regardless of the
 * decision — it describes how much trouble the request is in, which is still
 * meaningful while everything is under the threshold.
 */
function strictest(verdicts: RateLimitVerdict[]): RateLimitVerdict {
    let allowed = true;
    let retryAfter = 0;
    let failures = 0;

    for (const v of verdicts) {
        if (!v.allowed) {
            allowed = false;
            retryAfter = Math.max(retryAfter, v.retryAfter);
        }
        failures = Math.max(failures, v.failures);
    }
    return { allowed, retryAfter, failures };
}

export async function checkRateLimit(env: Env, subjects: string[]): Promise<RateLimitVerdict> {
    return strictest(await Promise.all(subjects.map(s => stub(env, s).peek())));
}

export async function recordFailure(
    env: Env,
    subjects: string[],
    policy: LimitPolicy = CREDENTIAL_POLICY
): Promise<RateLimitVerdict> {
    return strictest(await Promise.all(subjects.map(s => stub(env, s).fail(policy))));
}

export async function clearRateLimit(env: Env, subjects: string[]): Promise<void> {
    await Promise.all(subjects.map(s => stub(env, s).reset()));
}
