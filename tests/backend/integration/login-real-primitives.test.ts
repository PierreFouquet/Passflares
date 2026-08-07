// Login, end to end, with nothing standing in for the thing under test.
//
// tests/backend/auth.test.ts mocks deriveScryptHash to a constant, so both
// sides of `timingSafeEqualHex(verifiedHash, user.password_hash)` are the same
// test-controlled value and the comparison cannot fail — deleting it outright
// keeps that suite green (#83). Here scrypt is real and the row comes from real
// SQLite, so a wrong secret is rejected because the hashes genuinely differ.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createTestD1, createTestR2, type TestD1 } from '../../mocks/d1.js';
import { createMockRateLimiter, makeRequest, mockCtx } from '../../mocks/cloudflare.js';

vi.mock('../../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

const { handleRegister, handleLogin, handleDeleteAccount } = await import('../../../src/auth.js');

const KDF_PARAMS = { m: 47104, t: 1, p: 1, len: 32 };
const RIGHT_SECRET = 'a'.repeat(64);
const WRONG_SECRET = 'b'.repeat(64);

const registration = (email: string, authSecret: string) => ({
    email,
    authSecret,
    kdfSalt: 'b'.repeat(32),
    kdfParams: KDF_PARAMS,
    publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE' + 'x'.repeat(50),
    privateKeyEnc: 'aabbccddeeff001122334455:9988776655',
    turnstileToken: 'valid-token'
});

let d1: TestD1;
let env: any;

beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(async () =>
        new Response(JSON.stringify({ success: true }), { status: 200 })));
    d1 = createTestD1();
    env = {
        DB: d1,
        VAULTS: createTestR2(),
        RATE_LIMITER: createMockRateLimiter(),
        JWT_SECRET: 'test-jwt-secret-32-chars-minimum!!',
        TURNSTILE_KEY: 'test-turnstile-key',
        TOTP_ENC_KEY: 'test-totp-enc-key-32-chars-minimum!!'
    };
});

afterEach(() => vi.unstubAllGlobals());

const register = (email: string, authSecret: string) =>
    handleRegister(makeRequest('POST', '/api/register', registration(email, authSecret)) as any, env, mockCtx);

const login = (email: string, authSecret: string) =>
    handleLogin(makeRequest('POST', '/api/login', {
        email, authSecret, turnstileToken: 'valid-token'
    }) as any, env, mockCtx);

describe('login against real scrypt and real SQL', () => {
    it('stores a hash that is neither the secret nor a constant', async () => {
        expect((await register('real@example.com', RIGHT_SECRET)).status).toBe(201);

        const [row] = d1.query<{ password_hash: string; password_salt: string }>(
            'SELECT password_hash, password_salt FROM users WHERE email = ?', 'real@example.com'
        );

        expect(row.password_hash).toBeTruthy();
        expect(row.password_hash).not.toBe(RIGHT_SECRET);
        expect(row.password_hash).not.toBe(row.password_salt);
    });

    it('derives a different hash for a different secret under the same salt', async () => {
        await register('a@example.com', RIGHT_SECRET);
        await register('b@example.com', WRONG_SECRET);

        const rows = d1.query<{ password_hash: string }>(
            'SELECT password_hash FROM users ORDER BY id'
        );
        expect(rows[0].password_hash).not.toBe(rows[1].password_hash);
    });

    it('accepts the correct auth secret', async () => {
        await register('real@example.com', RIGHT_SECRET);
        const res = await login('real@example.com', RIGHT_SECRET);

        expect(res.status).toBe(200);
        expect((await res.json() as any).token).toBeTruthy();
    });

    it('rejects a wrong auth secret with 401 and no token', async () => {
        await register('real@example.com', RIGHT_SECRET);
        const res = await login('real@example.com', WRONG_SECRET);

        expect(res.status).toBe(401);
        expect((await res.json() as any).token).toBeUndefined();
    });

    it('rejects an unknown account with 401', async () => {
        await register('real@example.com', RIGHT_SECRET);
        expect((await login('nobody@example.com', RIGHT_SECRET)).status).toBe(401);
    });

    it('will not sign one account in with another account’s secret', async () => {
        await register('alice@example.com', RIGHT_SECRET);
        await register('mallory@example.com', WRONG_SECRET);

        expect((await login('alice@example.com', WRONG_SECRET)).status).toBe(401);
    });
});

// Deleting an account is irreversible and sits behind a session token, so the
// password re-check is the only thing standing between a stolen token and data
// loss. Nothing exercised it before #83.
describe('account deletion re-verifies the master password', () => {
    async function deleteAccount(userId: number, authSecret: string) {
        const req = makeRequest('DELETE', `/api/users/${userId}`, { authSecret }) as any;
        req.user = { userId, email: 'real@example.com', iat: 0, exp: 9999999999 };
        req.params = { userId: String(userId) };
        return handleDeleteAccount(req, env, mockCtx);
    }

    async function registerAndGetId(): Promise<number> {
        await register('real@example.com', RIGHT_SECRET);
        return d1.query<{ id: number }>('SELECT id FROM users WHERE email = ?', 'real@example.com')[0].id;
    }

    const userCount = () => d1.query<{ c: number }>('SELECT COUNT(*) c FROM users')[0].c;

    it('rejects the wrong secret and keeps the account', async () => {
        const id = await registerAndGetId();

        expect((await deleteAccount(id, WRONG_SECRET)).status).toBe(401);
        expect(userCount()).toBe(1);
    });

    it('deletes the account when the secret is correct', async () => {
        const id = await registerAndGetId();

        expect((await deleteAccount(id, RIGHT_SECRET)).status).toBe(204);
        expect(userCount()).toBe(0);
    });

    it('will not let one account be deleted with another account’s secret', async () => {
        const alice = await registerAndGetId();
        await register('mallory@example.com', WRONG_SECRET);

        expect((await deleteAccount(alice, WRONG_SECRET)).status).toBe(401);
        expect(userCount()).toBe(2);
    });
});
