// Regression tests for GHSA-q9vh-jccv-9p23 — "Recovery codes can be redeemed
// more than once (TOCTOU); some 2FA verify paths are unthrottled".
//
// Two separate defects:
//
//   1. consumeRecoveryCode did SELECT-then-UPDATE with no serialisation, so two
//      concurrent requests presenting the same code both saw `used_at IS NULL`
//      and both succeeded. Recovery codes are meant to be strictly single-use.
//
//   2. handleTotpEnable, handleTotpDisable, the change-authenticator branch of
//      handleTotpEnroll, and handleRegenerateRecoveryCodes had no attempt cap at
//      all — unlimited guesses against a 6-digit code.

import { describe, it, expect, vi } from 'vitest';
import { sign } from 'jsonwebtoken';
import { TOTP, Secret } from 'otpauth';
import {
    handleTotpEnroll,
    handleTotpEnable,
    handleTotpDisable,
    handleRegenerateRecoveryCodes,
    handleLoginVerify2fa,
    __testables
} from '../../src/totp.js';
import { createMockRateLimiter } from '../mocks/cloudflare.js';
import { recordFailure } from '../../src/rateLimiter.js';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

const SECRET = 'test-jwt-secret-32-chars-minimum!!';
const ENC_KEY = 'test-totp-enc-key-32-chars-minimum!!';
const mockCtx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;

function totpCode(base32: string): string {
    return new TOTP({ secret: Secret.fromBase32(base32), digits: 6, period: 30, algorithm: 'SHA1' }).generate();
}

/**
 * A recovery-code store with SQLite's semantics, driving the *real*
 * consumeRecoveryCode.
 *
 * It faithfully serves both statement shapes — the SELECT the racy version used
 * and the guarded UPDATE the fix uses — so the test distinguishes the two
 * implementations rather than restating whichever one is current.
 *
 * `await tick()` inside each statement models the round trip to D1: that is the
 * suspension point at which the old SELECT-then-UPDATE let another request in.
 */
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

function makeRecoveryStore(hashes: string[]) {
    const rows = hashes.map((code_hash, i) => ({ id: i + 1, user_id: 1, code_hash, used_at: null as string | null }));
    return {
        rows,
        env: {
            TOTP_ENC_KEY: ENC_KEY,
            DB: {
                prepare: (sql: string) => ({
                    bind: (...args: any[]) => ({
                        first: async () => {
                            await tick();
                            if (/SELECT id FROM user_recovery_codes/.test(sql)) {
                                const [userId, hash] = args;
                                const row = rows.find(r => r.user_id === userId && r.code_hash === hash && r.used_at === null);
                                return row ? { id: row.id } : null;
                            }
                            return null;
                        },
                        run: async () => {
                            await tick();
                            // Guarded form: the predicate is part of the write,
                            // so whoever arrives second matches nothing.
                            if (/UPDATE user_recovery_codes SET used_at[\s\S]*used_at IS NULL/.test(sql)) {
                                const [userId, hash] = args;
                                const row = rows.find(r => r.user_id === userId && r.code_hash === hash && r.used_at === null);
                                if (row) row.used_at = 'now';
                                return { success: true, meta: { changes: row ? 1 : 0 } };
                            }
                            // Unguarded form: UPDATE ... WHERE id = ?, which
                            // happily re-stamps a row someone else already spent.
                            if (/UPDATE user_recovery_codes SET used_at/.test(sql)) {
                                const row = rows.find(r => r.id === args[0]);
                                if (row) row.used_at = 'now';
                                return { success: true, meta: { changes: row ? 1 : 0 } };
                            }
                            return { success: true, meta: { changes: 0 } };
                        },
                        all: async () => ({ results: [], success: true })
                    })
                }),
                batch: async () => []
            } as unknown as D1Database
        } as any
    };
}

describe('GHSA-q9vh-jccv-9p23 — a recovery code is redeemable exactly once', () => {
    // The advisory's core scenario. Under SELECT-then-UPDATE both of these
    // succeeded; the guarded UPDATE lets exactly one win.
    it('lets only one of two concurrent redemptions of the same code succeed', async () => {
        const code = 'ABCDE-FGHJK';
        const { env, rows } = makeRecoveryStore([__testables.hashRecoveryCode({ TOTP_ENC_KEY: ENC_KEY } as any, code)]);

        const [a, b] = await Promise.all([
            __testables.consumeRecoveryCode(env, 1, code),
            __testables.consumeRecoveryCode(env, 1, code)
        ]);

        expect([a, b].filter(Boolean)).toHaveLength(1);
        expect(rows[0].used_at).not.toBeNull();
    });

    it('rejects a code that has already been spent', async () => {
        const code = 'ABCDE-FGHJK';
        const { env } = makeRecoveryStore([__testables.hashRecoveryCode({ TOTP_ENC_KEY: ENC_KEY } as any, code)]);

        expect(await __testables.consumeRecoveryCode(env, 1, code)).toBe(true);
        expect(await __testables.consumeRecoveryCode(env, 1, code)).toBe(false);
        expect(await __testables.consumeRecoveryCode(env, 1, code)).toBe(false);
    });

    it('rejects a code that was never issued', async () => {
        const { env } = makeRecoveryStore([__testables.hashRecoveryCode({ TOTP_ENC_KEY: ENC_KEY } as any, 'AAAAA-BBBBB')]);
        expect(await __testables.consumeRecoveryCode(env, 1, 'ZZZZZ-YYYYY')).toBe(false);
    });

    it('never redeems more codes than were issued, however many callers race', async () => {
        const codes = ['AAAAA-BBBBB', 'CCCCC-DDDDD', 'EEEEE-FFFFF'];
        const keyEnv = { TOTP_ENC_KEY: ENC_KEY } as any;
        const { env, rows } = makeRecoveryStore(codes.map(c => __testables.hashRecoveryCode(keyEnv, c)));

        // Ten simultaneous attempts per code.
        const attempts = codes.flatMap(c =>
            Array.from({ length: 10 }, () => __testables.consumeRecoveryCode(env, 1, c))
        );
        const wins = (await Promise.all(attempts)).filter(Boolean).length;

        expect(wins).toBe(3);
        expect(rows.every(r => r.used_at !== null)).toBe(true);
    });

    it('scopes redemption to the owning account', async () => {
        const code = 'AAAAA-BBBBB';
        const { env } = makeRecoveryStore([__testables.hashRecoveryCode({ TOTP_ENC_KEY: ENC_KEY } as any, code)]);
        // The row belongs to user 1; user 2 presenting the same string gets nothing.
        expect(await __testables.consumeRecoveryCode(env, 2, code)).toBe(false);
        expect(await __testables.consumeRecoveryCode(env, 1, code)).toBe(true);
    });
});

// ── Throttling on the previously-uncapped paths ─────────────────────────────

interface World {
    totp: { user_id: number; secret_enc: string | null; pending_secret_enc: string | null; enabled: number; confirmed_at: string | null } | null;
    passwordHash: string;
    passwordSalt: string;
}

function makeEnv(world: World, rateLimiter = createMockRateLimiter()) {
    return {
        RATE_LIMITER: rateLimiter,
        JWT_SECRET: SECRET,
        TOTP_ENC_KEY: ENC_KEY,
        DB: {
            prepare: (sql: string) => ({
                bind: (..._args: any[]) => ({
                    first: async () => {
                        if (sql.includes('FROM user_totp WHERE user_id')) return world.totp;
                        if (sql.includes('password_hash, password_salt FROM users')) {
                            return { password_hash: world.passwordHash, password_salt: world.passwordSalt };
                        }
                        return null;
                    },
                    run: async () => ({ success: true, meta: { changes: 0 } }),
                    all: async () => ({ results: [], success: true })
                })
            }),
            batch: async () => []
        } as unknown as D1Database
    } as any;
}

function authedReq(body: any, userId = 1, email = 'u@example.com') {
    const req: any = new Request('https://passflares.test/api/2fa/x', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    req.user = { userId, email };
    return req;
}

async function enabledWorld(): Promise<World> {
    const secret = new Secret({ size: 20 }).base32;
    const env = { TOTP_ENC_KEY: ENC_KEY } as any;
    const enc = await __testables.encryptSecret(env, secret);
    return {
        totp: { user_id: 1, secret_enc: enc, pending_secret_enc: null, enabled: 1, confirmed_at: 'now' },
        // A hash nothing will match, so every re-auth in these tests fails.
        passwordHash: 'a'.repeat(64),
        passwordSalt: 'b'.repeat(32)
    };
}

describe('GHSA-q9vh-jccv-9p23 — the 2FA management paths are throttled', () => {
    // Before the fix these four accepted unlimited guesses. handleTotpEnable is
    // the sharpest: ~3 codes are valid at a time under window:1, so an uncapped
    // endpoint falls to roughly 333k attempts.
    it('caps guesses on 2FA enable', async () => {
        const secret = new Secret({ size: 20 }).base32;
        const enc = await __testables.encryptSecret({ TOTP_ENC_KEY: ENC_KEY } as any, secret);
        const world: World = {
            totp: { user_id: 1, secret_enc: null, pending_secret_enc: enc, enabled: 0, confirmed_at: null },
            passwordHash: 'a'.repeat(64),
            passwordSalt: 'b'.repeat(32)
        };
        const env = makeEnv(world);

        // Five wrong codes, then the sixth attempt is refused outright.
        for (let i = 0; i < 5; i++) {
            const res = await handleTotpEnable(authedReq({ code: '000000' }), env, mockCtx);
            expect(res.status).toBe(401);
        }
        const blocked = await handleTotpEnable(authedReq({ code: '000000' }), env, mockCtx);
        expect(blocked.status).toBe(429);
        expect(blocked.headers.get('Retry-After')).toMatch(/^\d+$/);
    });

    it('a correct code still works once the budget is untouched', async () => {
        const secret = new Secret({ size: 20 }).base32;
        const enc = await __testables.encryptSecret({ TOTP_ENC_KEY: ENC_KEY } as any, secret);
        const world: World = {
            totp: { user_id: 1, secret_enc: null, pending_secret_enc: enc, enabled: 0, confirmed_at: null },
            passwordHash: 'a'.repeat(64),
            passwordSalt: 'b'.repeat(32)
        };
        const env = makeEnv(world);

        const res = await handleTotpEnable(authedReq({ code: totpCode(secret) }), env, mockCtx);
        expect(res.status).toBe(200);
    });

    it('caps guesses on 2FA disable', async () => {
        const env = makeEnv(await enabledWorld());
        for (let i = 0; i < 5; i++) {
            const res = await handleTotpDisable(authedReq({ authSecret: 'wrong', code: '000000' }), env, mockCtx);
            expect(res.status).toBe(401);
        }
        expect((await handleTotpDisable(authedReq({ authSecret: 'wrong', code: '000000' }), env, mockCtx)).status).toBe(429);
    });

    it('caps guesses on the change-authenticator branch of enroll', async () => {
        const env = makeEnv(await enabledWorld());
        for (let i = 0; i < 5; i++) {
            const res = await handleTotpEnroll(authedReq({ authSecret: 'wrong', code: '000000' }), env, mockCtx);
            expect(res.status).toBe(401);
        }
        expect((await handleTotpEnroll(authedReq({ authSecret: 'wrong', code: '000000' }), env, mockCtx)).status).toBe(429);
    });

    it('caps guesses on recovery-code regeneration', async () => {
        const env = makeEnv(await enabledWorld());
        for (let i = 0; i < 5; i++) {
            const res = await handleRegenerateRecoveryCodes(authedReq({ authSecret: 'wrong' }), env, mockCtx);
            expect(res.status).toBe(401);
        }
        expect((await handleRegenerateRecoveryCodes(authedReq({ authSecret: 'wrong' }), env, mockCtx)).status).toBe(429);
    });

    // All four share one budget per account, so an attacker cannot get five
    // fresh guesses per endpoint by rotating between them.
    it('shares one budget across the management endpoints', async () => {
        const env = makeEnv(await enabledWorld());

        await handleTotpDisable(authedReq({ authSecret: 'wrong', code: '000000' }), env, mockCtx);
        await handleTotpDisable(authedReq({ authSecret: 'wrong', code: '000000' }), env, mockCtx);
        await handleRegenerateRecoveryCodes(authedReq({ authSecret: 'wrong' }), env, mockCtx);
        await handleRegenerateRecoveryCodes(authedReq({ authSecret: 'wrong' }), env, mockCtx);
        await handleTotpEnroll(authedReq({ authSecret: 'wrong', code: '000000' }), env, mockCtx);

        // Five failures spread over three endpoints exhausts the shared budget.
        expect((await handleTotpDisable(authedReq({ authSecret: 'wrong', code: '000000' }), env, mockCtx)).status).toBe(429);
    });

    // These endpoints are keyed per account with no IP component. Both halves
    // matter: an attacker must not get a fresh budget by changing source, and a
    // colleague behind the same office NAT must not be collateral damage.
    it('keeps accounts independent — one throttled user does not block another', async () => {
        const env = makeEnv(await enabledWorld());
        for (let i = 0; i < 5; i++) {
            await handleRegenerateRecoveryCodes(authedReq({ authSecret: 'wrong' }, 1), env, mockCtx);
        }
        expect((await handleRegenerateRecoveryCodes(authedReq({ authSecret: 'wrong' }, 1), env, mockCtx)).status).toBe(429);
        // Different account, same source: gets its own budget.
        expect((await handleRegenerateRecoveryCodes(authedReq({ authSecret: 'wrong' }, 2), env, mockCtx)).status).toBe(401);
    });

    it('does not hand out a fresh budget when the attacker changes IP', async () => {
        const env = makeEnv(await enabledWorld());
        const fromIp = (ip: string) => {
            const req: any = new Request('https://passflares.test/api/2fa/recovery-codes/regenerate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
                body: JSON.stringify({ authSecret: 'wrong' })
            });
            req.user = { userId: 1, email: 'u@example.com' };
            return req;
        };

        for (let i = 0; i < 5; i++) {
            await handleRegenerateRecoveryCodes(fromIp(`203.0.113.${i}`), env, mockCtx);
        }
        expect((await handleRegenerateRecoveryCodes(fromIp('198.51.100.99'), env, mockCtx)).status).toBe(429);
    });
});

describe('GHSA-q9vh-jccv-9p23 — the login 2FA step reports Retry-After', () => {
    it('answers 429 with a Retry-After header once the IP budget is spent', async () => {
        const env = makeEnv(await enabledWorld());
        for (let i = 0; i < 5; i++) await recordFailure(env, ['2fa:ip:unknown']);

        const temp = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const req: any = new Request('https://passflares.test/api/login/2fa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tempToken: temp, code: '000000' })
        });

        const res = await handleLoginVerify2fa(req, env, mockCtx);
        expect(res.status).toBe(429);
        expect(res.headers.get('Retry-After')).toMatch(/^\d+$/);
    });
});
