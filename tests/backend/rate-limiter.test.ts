// Regression tests for GHSA-vp89-22wm-gjr8 — "KV brute-force limiter is
// bypassable via concurrent requests (non-atomic counter)".
//
// The defect was a read-modify-write against Workers KV:
//
//     const n = await env.RATE_LIMIT.get(key);        // READ
//     if (n && parseInt(n) >= LIMIT) return 429;
//     await env.RATE_LIMIT.put(key, String(n + 1));   // WRITE
//
// N requests dispatched together all read the same value, all compute the same
// n+1, and all write it. N guesses, one increment.
//
// Every test below was checked against the old implementation before the fix
// landed; the concurrency tests are the ones that were red.

import { describe, it, expect } from 'vitest';
import {
    RateLimiter,
    checkRateLimit,
    recordFailure,
    clearRateLimit,
    lockoutFor,
    ipSubject,
    accountSubject,
    FAILURE_THRESHOLD,
    BASE_LOCKOUT_MS,
    MAX_LOCKOUT_MS,
    CREDENTIAL_POLICY,
    VOLUME_POLICY
} from '../../src/rateLimiter.js';
import { createMockRateLimiter, createMockDurableObjectState } from '../mocks/cloudflare.js';

function env() {
    return { RATE_LIMITER: createMockRateLimiter() } as any;
}

describe('lockoutFor — exponential backoff', () => {
    it('permits everything below the threshold', () => {
        for (let i = 0; i < FAILURE_THRESHOLD; i++) {
            expect(lockoutFor(i)).toBe(0);
        }
    });

    it('applies the base lockout at the threshold, matching the old flat window', () => {
        expect(lockoutFor(FAILURE_THRESHOLD)).toBe(BASE_LOCKOUT_MS);
    });

    it('doubles for each failure past the threshold', () => {
        expect(lockoutFor(FAILURE_THRESHOLD + 1)).toBe(BASE_LOCKOUT_MS * 2);
        expect(lockoutFor(FAILURE_THRESHOLD + 2)).toBe(BASE_LOCKOUT_MS * 4);
        expect(lockoutFor(FAILURE_THRESHOLD + 3)).toBe(BASE_LOCKOUT_MS * 8);
    });

    it('caps rather than growing without bound — a lockout is never permanent', () => {
        expect(lockoutFor(FAILURE_THRESHOLD + 100)).toBe(MAX_LOCKOUT_MS);
        // 2 ** 1024 is Infinity; an unclamped shift would produce NaN here and
        // NaN comparisons are always false, i.e. never locked out.
        expect(Number.isFinite(lockoutFor(100000))).toBe(true);
    });

    it('honours a looser policy for volume limits', () => {
        expect(lockoutFor(10, VOLUME_POLICY)).toBe(0);
        expect(lockoutFor(VOLUME_POLICY.threshold, VOLUME_POLICY)).toBe(VOLUME_POLICY.baseLockoutMs);
    });
});

describe('RateLimiter — counting', () => {
    it('starts unlocked with no recorded failures', async () => {
        const e = env();
        const verdict = await checkRateLimit(e, ['login:ip:203.0.113.1']);
        expect(verdict).toEqual({ allowed: true, retryAfter: 0, failures: 0 });
    });

    it('increments once per failure and blocks at the threshold', async () => {
        const e = env();
        const subject = ['login:ip:203.0.113.1'];

        for (let i = 1; i < FAILURE_THRESHOLD; i++) {
            const v = await recordFailure(e, subject);
            expect(v.failures).toBe(i);
            expect(v.allowed).toBe(true);
        }

        const blocked = await recordFailure(e, subject);
        expect(blocked.failures).toBe(FAILURE_THRESHOLD);
        expect(blocked.allowed).toBe(false);
        expect(blocked.retryAfter).toBeGreaterThan(0);
        expect((await checkRateLimit(e, subject)).allowed).toBe(false);
    });

    it('clears on success', async () => {
        const e = env();
        const subject = ['login:ip:203.0.113.1'];
        for (let i = 0; i < FAILURE_THRESHOLD; i++) await recordFailure(e, subject);
        expect((await checkRateLimit(e, subject)).allowed).toBe(false);

        await clearRateLimit(e, subject);
        expect(await checkRateLimit(e, subject)).toEqual({ allowed: true, retryAfter: 0, failures: 0 });
    });

    it('keeps subjects independent — one locked account does not lock another', async () => {
        const e = env();
        const mine = ['login:account:victim@example.com'];
        const theirs = ['login:account:bystander@example.com'];

        for (let i = 0; i < FAILURE_THRESHOLD; i++) await recordFailure(e, mine);

        expect((await checkRateLimit(e, mine)).allowed).toBe(false);
        expect((await checkRateLimit(e, theirs)).allowed).toBe(true);
    });
});

// ── The actual advisory ──────────────────────────────────────────────────────

describe('GHSA-vp89-22wm-gjr8 — concurrent requests cannot outrun the counter', () => {
    // Reproduces the advisory's repro step 2 ("fire 50 POST /api/login for one
    // email in parallel") at the limiter level. Under the KV implementation the
    // counter landed on 1, not 50 — every increment read the same stale zero.
    it('counts every one of 50 simultaneous failures', async () => {
        const e = env();
        const subject = ['login:account:victim@example.com'];

        const verdicts = await Promise.all(
            Array.from({ length: 50 }, () => recordFailure(e, subject))
        );

        const final = await checkRateLimit(e, subject);
        expect(final.failures).toBe(50);
        expect(final.allowed).toBe(false);

        // Only the first FAILURE_THRESHOLD - 1 may be told they are still allowed.
        const allowed = verdicts.filter(v => v.allowed).length;
        expect(allowed).toBeLessThan(FAILURE_THRESHOLD);
    });

    it('never loses an increment across interleaved batches', async () => {
        const e = env();
        const subject = ['2fa:account:1'];

        for (let batch = 0; batch < 4; batch++) {
            await Promise.all(Array.from({ length: 10 }, () => recordFailure(e, subject)));
        }

        expect((await checkRateLimit(e, subject)).failures).toBe(40);
    });

    // The storage read and write must both be inside one method call. If a
    // caller could observe state between them — which is exactly what the KV
    // version exposed — the increment is racy again.
    it('performs its read and write within a single object method', async () => {
        const state = createMockDurableObjectState();
        const limiter = new RateLimiter(state, {} as any);

        await limiter.fail();
        const putsAfterOne = (state.storage.put as any).mock.calls.length;
        expect(putsAfterOne).toBe(1);

        // A second failure must read what the first wrote, not a cached zero.
        const second = await limiter.fail();
        expect(second.failures).toBe(2);
    });
});

describe('GHSA-vp89-22wm-gjr8 — the limit is per account as well as per IP', () => {
    // An IP-only cap is sidestepped by a distributed attacker, and conversely
    // lets one abuser lock out a whole NAT egress. Both directions tested.
    it('blocks a distributed attack on one account from many IPs', async () => {
        const e = env();
        const email = 'victim@example.com';

        // Each request from a different source IP — the IP buckets never fill.
        for (let i = 0; i < FAILURE_THRESHOLD; i++) {
            await recordFailure(e, [
                ipSubject('login', `203.0.113.${i}`),
                accountSubject('login', email)
            ]);
        }

        const fromYetAnotherIp = await checkRateLimit(e, [
            ipSubject('login', '198.51.100.200'),
            accountSubject('login', email)
        ]);
        expect(fromYetAnotherIp.allowed).toBe(false);
    });

    it('does not let one abused account lock out other users on the same IP', async () => {
        const e = env();
        const sharedIp = '203.0.113.50';

        // Five failures spread across five accounts: no single account bucket
        // reaches the threshold, but the shared IP bucket does.
        for (let i = 0; i < FAILURE_THRESHOLD; i++) {
            await recordFailure(e, [accountSubject('login', `user${i}@example.com`)]);
        }

        const innocent = await checkRateLimit(e, [
            ipSubject('login', sharedIp),
            accountSubject('login', 'innocent@example.com')
        ]);
        expect(innocent.allowed).toBe(true);
    });

    it('reports the strictest verdict when several subjects apply', async () => {
        const e = env();
        const ip = ipSubject('login', '203.0.113.9');
        const account = accountSubject('login', 'someone@example.com');

        // Push the account far past the threshold so its lockout is the longer one.
        for (let i = 0; i < FAILURE_THRESHOLD + 3; i++) await recordFailure(e, [account]);
        for (let i = 0; i < FAILURE_THRESHOLD; i++) await recordFailure(e, [ip]);

        const combined = await checkRateLimit(e, [ip, account]);
        const accountOnly = await checkRateLimit(e, [account]);
        expect(combined.allowed).toBe(false);
        expect(combined.retryAfter).toBe(accountOnly.retryAfter);
    });
});

describe('RateLimiter — housekeeping', () => {
    it('schedules an alarm so an idle subject evaporates instead of leaking storage', async () => {
        const state = createMockDurableObjectState();
        const limiter = new RateLimiter(state, {} as any);

        expect(await state.storage.getAlarm()).toBeNull();
        await limiter.fail();
        expect(await state.storage.getAlarm()).toBeGreaterThan(Date.now());
    });

    it('wipes storage when the alarm fires', async () => {
        const state = createMockDurableObjectState();
        const limiter = new RateLimiter(state, {} as any);

        await limiter.fail();
        expect(state._store.size).toBeGreaterThan(0);

        await limiter.alarm();
        expect(state._store.size).toBe(0);
    });

    it('forgives a subject that has been idle past the decay window', async () => {
        const state = createMockDurableObjectState();
        const limiter = new RateLimiter(state, {} as any);

        await limiter.fail();
        // Rewrite the stored state as if it were written two hours ago and any
        // lockout has already expired.
        const stale = state._store.get('state') as any;
        state._store.set('state', { ...stale, updatedAt: Date.now() - 2 * 60 * 60 * 1000, lockedUntil: 0 });

        expect((await limiter.peek()).failures).toBe(0);
    });

    it('does not forgive while a lockout is still running', async () => {
        const state = createMockDurableObjectState();
        const limiter = new RateLimiter(state, {} as any);

        for (let i = 0; i < FAILURE_THRESHOLD; i++) await limiter.fail();
        const locked = state._store.get('state') as any;
        // Old updatedAt, but the lockout itself has not expired.
        state._store.set('state', { ...locked, updatedAt: Date.now() - 2 * 60 * 60 * 1000 });

        const verdict = await limiter.peek();
        expect(verdict.allowed).toBe(false);
        expect(verdict.failures).toBe(FAILURE_THRESHOLD);
    });

    it('uses the credential policy by default', async () => {
        const state = createMockDurableObjectState();
        const limiter = new RateLimiter(state, {} as any);

        for (let i = 0; i < CREDENTIAL_POLICY.threshold - 1; i++) {
            expect((await limiter.fail()).allowed).toBe(true);
        }
        expect((await limiter.fail()).allowed).toBe(false);
    });
});
