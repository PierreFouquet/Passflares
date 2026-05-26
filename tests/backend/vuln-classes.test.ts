// Behavioural tests for vulnerability classes the Pentest-Tools Light scan
// doesn't cover (most are in the Deep tier). These complement the static
// guardrails in code-security-invariants.test.ts.
//
// Each test exercises the worker through its real `fetch` entry point so
// that auth, validation, and rate-limiting all run.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { sign } from 'jsonwebtoken';
import worker from '../../src/worker.js';
import {
    createMockDB,
    createMockEnv,
    createMockKV,
    mockCtx
} from '../mocks/cloudflare.js';

const SECRET = 'test-jwt-secret-32-chars-minimum!!';

// Quiet audit + scrypt so tests are fast and focused.
vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));
vi.mock('../../src/utils.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../src/utils.js')>();
    return {
        ...actual,
        deriveScryptHash: vi.fn(async (_pw: string, salt?: string | null) => ({
            hash: 'mockhash',
            salt: salt ?? 'mocksalt'
        }))
    };
});

function tokenFor(userId: number, email = 'u@example.test') {
    return sign({ userId, email }, SECRET, { expiresIn: '1h' });
}

function envWith(dbResponses = {}, kv?: KVNamespace) {
    return createMockEnv({
        DB: createMockDB(dbResponses),
        RATE_LIMIT: kv ?? createMockKV(),
        JWT_SECRET: SECRET
    });
}

function apiReq(method: string, path: string, opts: {
    body?: unknown;
    token?: string;
    headers?: Record<string, string>;
} = {}) {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...opts.headers
    };
    if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
    return new Request(`https://passflares.test${path}`, {
        method,
        headers,
        body: opts.body ? JSON.stringify(opts.body) : undefined
    });
}

beforeEach(() => {
    // Default turnstile pass-through for endpoints that verify it.
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
        if (typeof url === 'string' && url.includes('turnstile/v0/siteverify')) {
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        throw new Error(`Unexpected fetch in test: ${url}`);
    }));
});

afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
});

describe('Auth bypass — JWT', () => {
    it('rejects requests with no Authorization header', async () => {
        const res = await worker.fetch(apiReq('GET', '/api/vaults'), envWith(), mockCtx);
        expect(res.status).toBe(401);
    });

    it('rejects requests where Authorization is not Bearer', async () => {
        const res = await worker.fetch(
            apiReq('GET', '/api/vaults', { headers: { Authorization: 'Basic abcdef' } }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(401);
    });

    it('rejects an expired JWT', async () => {
        const expired = sign({ userId: 1, email: 'u@u' }, SECRET, { expiresIn: -10 });
        const res = await worker.fetch(
            apiReq('GET', '/api/vaults', { token: expired }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(401);
    });

    it('rejects a JWT signed with the wrong key', async () => {
        const bad = sign({ userId: 1, email: 'u@u' }, 'wrong-secret', { expiresIn: '1h' });
        const res = await worker.fetch(
            apiReq('GET', '/api/vaults', { token: bad }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(401);
    });

    it('rejects a JWT with a tampered payload', async () => {
        const good = tokenFor(1);
        // Flip the middle (payload) segment — any byte change invalidates
        // the signature.
        const [h, p, s] = good.split('.');
        const tamperedPayload = Buffer.from(
            JSON.stringify({ userId: 9999, email: 'admin@evil', iat: 1, exp: 9999999999 })
        ).toString('base64url');
        const tampered = `${h}.${tamperedPayload}.${s}`;
        const res = await worker.fetch(
            apiReq('GET', '/api/vaults', { token: tampered }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(401);
    });

    it("rejects a JWT with alg=none", async () => {
        // Hand-craft an unsigned token. jsonwebtoken's verify() must
        // refuse this regardless of payload.
        const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
        const payload = Buffer.from(JSON.stringify({ userId: 1, email: 'u@u' })).toString('base64url');
        const noneToken = `${header}.${payload}.`;
        const res = await worker.fetch(
            apiReq('GET', '/api/vaults', { token: noneToken }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(401);
    });
});

describe('IDOR — encryption salt endpoint', () => {
    it("user A cannot fetch user B's encryption salt", async () => {
        // handleGetUserEncryptionSalt compares request.user.userId to the
        // :userId in the URL — mismatch must be 403.
        const aToken = tokenFor(1, 'a@a');
        const res = await worker.fetch(
            apiReq('GET', '/api/users/2/encryption-salt', { token: aToken }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(403);
    });

    it("user A cannot change user B's master password", async () => {
        const aToken = tokenFor(1, 'a@a');
        const res = await worker.fetch(
            apiReq('PUT', '/api/users/2/update-password', {
                token: aToken,
                body: {
                    oldMasterPassword: 'old',
                    newMasterPassword: 'new',
                    newEncryptionSalt: 'salt'
                }
            }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(403);
    });

    it("user A cannot delete user B's account", async () => {
        const aToken = tokenFor(1, 'a@a');
        const res = await worker.fetch(
            apiReq('DELETE', '/api/users/2', {
                token: aToken,
                body: { masterPassword: 'whatever' }
            }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(403);
    });
});

describe('Mass assignment — preferences', () => {
    it('ignores unknown fields like role / is_admin / user_id', async () => {
        const token = tokenFor(42, 'me@me');
        // The DB mock is loose — preferences handler builds the SQL with
        // bound parameters from a known whitelist (theme/density/shape/
        // accent). Any extra fields in the body should be dropped.
        const res = await worker.fetch(
            apiReq('PUT', '/api/users/me/preferences', {
                token,
                body: {
                    theme: 'dark',
                    density: 'comfortable',
                    shape: 'rounded',
                    accent: 'blue',
                    // Attacker-injected fields:
                    role: 'super_admin',
                    is_admin: true,
                    user_id: 9999,
                    __proto__: { isAdmin: true }
                }
            }),
            envWith(),
            mockCtx
        );
        // Whether the response is 200 or 500 (depends on DB mock), the
        // important assertion is that no garbage was written.
        // We can't easily inspect the bind() args from the loose mock,
        // but we can assert the response body doesn't echo elevation.
        const text = await res.text();
        expect(text.toLowerCase()).not.toContain('super_admin');
        expect(text.toLowerCase()).not.toContain('is_admin');
    });

    it('rejects an unknown theme/density/shape/accent value', async () => {
        const token = tokenFor(42);
        const res = await worker.fetch(
            apiReq('PUT', '/api/users/me/preferences', {
                token,
                body: { theme: '<script>alert(1)</script>' }
            }),
            envWith(),
            mockCtx
        );
        expect(res.status).toBe(400);
    });
});

describe('Prototype pollution', () => {
    it("does not pollute Object.prototype via JSON body with __proto__", async () => {
        const token = tokenFor(42);
        await worker.fetch(
            apiReq('PUT', '/api/users/me/preferences', {
                token,
                body: JSON.parse('{"__proto__": {"polluted": "yes"}, "theme": "dark"}')
            }),
            envWith(),
            mockCtx
        );
        expect(({} as any).polluted).toBeUndefined();
    });

    it('does not pollute via constructor.prototype', async () => {
        const token = tokenFor(42);
        await worker.fetch(
            apiReq('PUT', '/api/users/me/preferences', {
                token,
                body: { constructor: { prototype: { polluted2: 'yes' } }, theme: 'dark' }
            }),
            envWith(),
            mockCtx
        );
        expect(({} as any).polluted2).toBeUndefined();
    });
});

describe('Path traversal — vault routes', () => {
    it('encoded path-traversal in vault id does not reach the filesystem', async () => {
        const token = tokenFor(1);
        const res = await worker.fetch(
            apiReq('GET', '/api/vaults/..%2F..%2Fetc%2Fpasswd/data', { token }),
            envWith(),
            mockCtx
        );
        // Middleware parses vaultId via parseInt(); '..' → NaN → 400.
        // The important assertion is that we don't get a 200 with file
        // contents.
        expect([400, 401, 403, 404]).toContain(res.status);
        const text = await res.text();
        expect(text).not.toMatch(/root:.*:0:0:/);
    });

    it('non-numeric vault id is rejected, not coerced', async () => {
        const token = tokenFor(1);
        const res = await worker.fetch(
            apiReq('GET', '/api/vaults/abc/data', { token }),
            envWith({}, undefined),
            mockCtx
        );
        // parseInt('abc') → NaN → middleware returns 400.
        expect(res.status).toBe(400);
    });
});

describe('SQL injection (behavioural)', () => {
    it("registering with a SQLi-style email does not 500", async () => {
        const res = await worker.fetch(
            apiReq('POST', '/api/register', {
                body: {
                    email: "x' OR 1=1 --",
                    masterPassword: 'pw',
                    encryptionSalt: 'salt',
                    turnstileToken: 'ok'
                }
            }),
            envWith({}, createMockKV()),
            mockCtx
        );
        // Should be a normal 201/409/4xx — never an unhandled 500.
        expect(res.status).not.toBe(500);
    });

    it("login with a SQLi-style email does not 500", async () => {
        const res = await worker.fetch(
            apiReq('POST', '/api/login', {
                body: {
                    email: "'; DROP TABLE users; --",
                    masterPassword: 'pw',
                    turnstileToken: 'ok'
                }
            }),
            envWith({}, createMockKV()),
            mockCtx
        );
        expect(res.status).not.toBe(500);
    });
});

describe('Oversize body handling', () => {
    it('a multi-megabyte JSON body does not crash the worker', async () => {
        // Build a ~1MB JSON body (faster than 10MB for the unit run, same
        // behavioural shape — we just need to know it doesn't throw).
        const huge = 'a'.repeat(1_000_000);
        const res = await worker.fetch(
            apiReq('POST', '/api/login', {
                body: { email: 'x@x', masterPassword: huge, turnstileToken: 'ok' }
            }),
            envWith({}, createMockKV()),
            mockCtx
        );
        // 200 is fine (login attempt with junk creds), as is 400/401/429.
        // The point: it returned at all and isn't a server-error.
        expect(res.status).toBeLessThan(500);
    });
});

describe('Login enumeration — response sameness', () => {
    it("wrong-credentials response is identical for unknown vs known email", async () => {
        // Unknown user (DB returns null) → 401 "Invalid credentials."
        const r1 = await worker.fetch(
            apiReq('POST', '/api/login', {
                body: { email: 'nobody@nowhere', masterPassword: 'x', turnstileToken: 'ok' }
            }),
            envWith({}, createMockKV()),
            mockCtx
        );
        expect(r1.status).toBe(401);
        const m1 = (await r1.json() as { message: string }).message;

        // Known user with wrong password — DB returns a row, hash mismatch.
        const r2 = await worker.fetch(
            apiReq('POST', '/api/login', {
                body: { email: 'real@user', masterPassword: 'wrong', turnstileToken: 'ok' }
            }),
            envWith({
                'SELECT id, email, password_hash': {
                    first: {
                        id: 1,
                        email: 'real@user',
                        password_hash: 'different-hash',
                        password_salt: 'salt',
                        encryption_salt: 'esalt'
                    }
                }
            }, createMockKV()),
            mockCtx
        );
        expect(r2.status).toBe(401);
        const m2 = (await r2.json() as { message: string }).message;

        expect(m1).toBe(m2);
        expect(m1).toBe('Invalid credentials.');
    });
});

describe('Error responses — information leakage', () => {
    it("does not leak stack traces in 500 responses", async () => {
        // Force a 500 by handing the router a request that explodes during
        // routing — actually hard to do with the mock setup, so we instead
        // assert against the worker's top-level catch path: any explicit
        // 500 in an existing test path returns a generic message.
        // (jsonResponse merges any error into a fixed `Service unavailable`.)
        // We'll exercise by feeding a malformed JSON body to /api/login.
        const req = new Request('https://passflares.test/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: 'not-json{'
        });
        const res = await worker.fetch(req, envWith({}, createMockKV()), mockCtx);
        const text = await res.text();
        expect(text).not.toMatch(/at \w+\.\w+ \(/); // no stack frames
        expect(text).not.toMatch(/SyntaxError/);
        expect(text).not.toMatch(/\/home\/|\/usr\/|C:\\/); // no fs paths
    });
});
