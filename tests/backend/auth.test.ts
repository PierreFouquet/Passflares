import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { sign, decode } from 'jsonwebtoken';
import {
    handleRegister,
    handleLogin,
    handleGetUserEncryptionSalt,
    handleUpdateMasterPassword
} from '../../src/auth.js';
import { createMockDB, createMockEnv, createMockKV, makeRequest, mockCtx } from '../mocks/cloudflare.js';

// Mock scrypt — it's tested separately in utils.test.ts and is too slow here.
// verifyTurnstile is mocked per-test by stubbing global.fetch so we can flip
// it between pass/fail without re-mocking the module.
vi.mock('../../src/utils.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../src/utils.js')>();
    return {
        ...actual,
        deriveScryptHash: vi.fn(async (_password: string, saltHex?: string | null) => ({
            hash: 'mockhash',
            salt: saltHex ?? 'mocksalt'
        }))
    };
});

// Mock audit logging to keep test output clean
vi.mock('../../src/auditLog.js', () => ({
    logAudit: vi.fn()
}));

const SECRET = 'test-jwt-secret-32-chars-minimum!!';
const VALID_TURNSTILE_TOKEN = 'valid-token';

function mockTurnstileResponse(success: boolean) {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
        if (typeof url === 'string' && url.includes('turnstile/v0/siteverify')) {
            return new Response(JSON.stringify({ success }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        throw new Error(`Unexpected fetch in test: ${url}`);
    }));
}

beforeEach(() => {
    mockTurnstileResponse(true);
});

afterEach(() => {
    vi.unstubAllGlobals();
});

function baseEnv(dbResponses = {}) {
    return createMockEnv({
        DB: createMockDB(dbResponses),
        RATE_LIMIT: createMockKV(),
        JWT_SECRET: SECRET
    });
}

// --- handleRegister ---

describe('handleRegister', () => {
    it('registers a new user successfully', async () => {
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        const req = makeRequest('POST', '/api/register', {
            email: 'test@example.com',
            masterPassword: 'Password123!',
            encryptionSalt: 'aabbcc',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(201);
        const body = await res.json() as any;
        expect(body.message).toMatch(/registered/i);
    });

    it('returns 409 when email already exists', async () => {
        const env = baseEnv({ 'SELECT id FROM users': { first: { id: 1 } } });
        const req = makeRequest('POST', '/api/register', {
            email: 'existing@example.com',
            masterPassword: 'Password123!',
            encryptionSalt: 'aabbcc',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(409);
    });

    it('returns 400 when required fields are missing', async () => {
        const env = baseEnv();
        const req = makeRequest('POST', '/api/register', { email: 'test@example.com' }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(400);
    });

    it('returns 403 when Turnstile token is missing', async () => {
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        const req = makeRequest('POST', '/api/register', {
            email: 'test@example.com',
            masterPassword: 'Password123!',
            encryptionSalt: 'aabbcc'
        }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(403);
        const body = await res.json() as any;
        expect(body.message).toMatch(/captcha/i);
    });

    it('returns 403 when Turnstile verification fails', async () => {
        mockTurnstileResponse(false);
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        const req = makeRequest('POST', '/api/register', {
            email: 'test@example.com',
            masterPassword: 'Password123!',
            encryptionSalt: 'aabbcc',
            turnstileToken: 'bad-token'
        }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 429 after 5 failed register attempts from the same IP', async () => {
        const kv = createMockKV();
        (kv as any).get = vi.fn(() => Promise.resolve('5'));
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        (env as any).RATE_LIMIT = kv;

        const req = makeRequest('POST', '/api/register', {
            email: 'test@example.com',
            masterPassword: 'Password123!',
            encryptionSalt: 'aabbcc',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(429);
    });
});

// --- handleLogin ---

describe('handleLogin', () => {
    const mockUser = {
        id: 1,
        email: 'test@example.com',
        password_hash: 'mockhash',
        password_salt: 'mocksalt',
        encryption_salt: 'encryptionsalt',
        totp_enabled: null
    };

    it('logs in successfully with correct credentials', async () => {
        const kv = createMockKV();
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: mockUser } });
        (env as any).RATE_LIMIT = kv;

        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            masterPassword: 'correct-password',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.token).toBeTruthy();
        expect(body.encryptionSalt).toBe('encryptionsalt');
    });

    it('withholds the session and returns a 2FA challenge when TOTP is enabled', async () => {
        // The LEFT JOIN surfaces totp_enabled=1, so handleLogin must NOT issue a
        // session token or leak the encryption salt — only a short-lived temp token.
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: { ...mockUser, totp_enabled: 1 } } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            masterPassword: 'correct-password',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.requires2FA).toBe(true);
        expect(body.tempToken).toBeTruthy();
        expect(body.token).toBeUndefined();
        expect(body.encryptionSalt).toBeUndefined();

        // The temp token is scoped to '2fa' and carries `sub`, not `userId`.
        const decoded = decode(body.tempToken) as any;
        expect(decoded.scope).toBe('2fa');
        expect(decoded.sub).toBe(mockUser.id);
        expect(decoded.userId).toBeUndefined();
    });

    it('returns 401 when user is not found', async () => {
        const env = baseEnv({ 'SELECT id, email': { first: null } });
        const req = makeRequest('POST', '/api/login', {
            email: 'nobody@example.com',
            masterPassword: 'password',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('returns 401 when password hash does not match', async () => {
        const userWithDifferentHash = { ...mockUser, password_hash: 'differenthash' };
        const env = baseEnv({ 'SELECT id, email': { first: userWithDifferentHash } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            masterPassword: 'wrong-password',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('returns 429 when IP is rate limited', async () => {
        const kv = createMockKV();
        (kv as any).get = vi.fn(() => Promise.resolve('5')); // 5 failed attempts
        const env = baseEnv();
        (env as any).RATE_LIMIT = kv;

        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            masterPassword: 'password',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(429);
    });

    it('returns 400 when fields are missing', async () => {
        const env = baseEnv();
        const req = makeRequest('POST', '/api/login', { email: 'test@example.com' }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(400);
    });

    it('returns 403 when Turnstile token is missing', async () => {
        const env = baseEnv({ 'SELECT id, email': { first: mockUser } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            masterPassword: 'correct-password'
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(403);
        const body = await res.json() as any;
        expect(body.message).toMatch(/captcha/i);
    });

    it('returns 403 when Turnstile verification fails', async () => {
        mockTurnstileResponse(false);
        const env = baseEnv({ 'SELECT id, email': { first: mockUser } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            masterPassword: 'correct-password',
            turnstileToken: 'bad-token'
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(403);
    });
});

// --- handleGetUserEncryptionSalt ---

describe('handleGetUserEncryptionSalt', () => {
    it('returns the encryption salt for the authenticated user', async () => {
        const env = baseEnv({
            'SELECT encryption_salt': { first: { encryption_salt: 'mysalt' } }
        });
        const req = makeRequest('GET', '/api/users/1/encryption-salt') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '1' };

        const res = await handleGetUserEncryptionSalt(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.encryptionSalt).toBe('mysalt');
    });

    it('returns 403 when user ID does not match token', async () => {
        const env = baseEnv();
        const req = makeRequest('GET', '/api/users/2/encryption-salt') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '2' };

        const res = await handleGetUserEncryptionSalt(req, env, mockCtx);
        expect(res.status).toBe(403);
    });
});

// --- handleUpdateMasterPassword ---

describe('handleUpdateMasterPassword', () => {
    const mockUser = { id: 1, password_hash: 'mockhash', password_salt: 'mocksalt' };

    it('updates the master password successfully', async () => {
        const env = baseEnv({ 'SELECT id, password_hash': { first: mockUser } });
        const req = makeRequest('PUT', '/api/users/1/update-password', {
            oldMasterPassword: 'old-password',
            newMasterPassword: 'new-password',
            newEncryptionSalt: 'newsalt'
        }) as any;
        req.user = { userId: 1 };
        req.params = { userId: '1' };

        const res = await handleUpdateMasterPassword(req, env, mockCtx);
        expect(res.status).toBe(200);
    });

    it('returns 401 when old password is wrong', async () => {
        const userWithDifferentHash = { ...mockUser, password_hash: 'differenthash' };
        const env = baseEnv({ 'SELECT id, password_hash': { first: userWithDifferentHash } });
        const req = makeRequest('PUT', '/api/users/1/update-password', {
            oldMasterPassword: 'wrong',
            newMasterPassword: 'new',
            newEncryptionSalt: 'salt'
        }) as any;
        req.user = { userId: 1 };
        req.params = { userId: '1' };

        const res = await handleUpdateMasterPassword(req, env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('returns 403 when user ID does not match token', async () => {
        const env = baseEnv();
        const req = makeRequest('PUT', '/api/users/99/update-password', {
            oldMasterPassword: 'old',
            newMasterPassword: 'new',
            newEncryptionSalt: 'salt'
        }) as any;
        req.user = { userId: 1 };
        req.params = { userId: '99' };

        const res = await handleUpdateMasterPassword(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 400 when fields are missing', async () => {
        const env = baseEnv();
        const req = makeRequest('PUT', '/api/users/1/update-password', {
            oldMasterPassword: 'old'
        }) as any;
        req.user = { userId: 1 };
        req.params = { userId: '1' };

        const res = await handleUpdateMasterPassword(req, env, mockCtx);
        expect(res.status).toBe(400);
    });
});
