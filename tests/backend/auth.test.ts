import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { sign, decode } from 'jsonwebtoken';
import {
    handleRegister,
    handleLogin,
    handleAuthParams,
    handleAuthUpgrade,
    handleGetUserEncryptionSalt,
    handleGetUserPublicKey,
    handleUpdateMasterPassword
} from '../../src/auth.js';
import { createMockDB, createMockEnv, createMockKV, makeRequest, mockCtx } from '../mocks/cloudflare.js';

// Mock scrypt — it's tested separately in utils.test.ts and is too slow here.
// The stand-in hash must be valid hex: timingSafeEqualHex compares decoded bytes
// and treats anything non-hex as a mismatch, which is the correct fail-closed
// behaviour but would make a non-hex placeholder never match itself.
const MOCK_HASH = 'deadbeefdeadbeefdeadbeefdeadbeef';

vi.mock('../../src/utils.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../src/utils.js')>();
    return {
        ...actual,
        deriveScryptHash: vi.fn(async (_secret: string, saltHex?: string | null) => ({
            hash: 'deadbeefdeadbeefdeadbeefdeadbeef',
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

// A well-formed auth_version 2 registration payload. Note what it does not
// contain: the master password. The client has already run Argon2id + HKDF.
const KDF_PARAMS = { m: 47104, t: 1, p: 1, len: 32 };
const V2_REGISTRATION = {
    email: 'test@example.com',
    authSecret: 'a'.repeat(64),
    kdfSalt: 'b'.repeat(32),
    kdfParams: KDF_PARAMS,
    publicKey: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE' + 'x'.repeat(50),
    privateKeyEnc: 'aabbccddeeff001122334455:9988776655',
    turnstileToken: VALID_TURNSTILE_TOKEN
};

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

// --- handleAuthParams ---

describe('handleAuthParams', () => {
    it('returns the stored Argon2id parameters for a known v2 account', async () => {
        const env = baseEnv({
            'SELECT auth_version': {
                first: { auth_version: 2, kdf_salt: 'c'.repeat(32), kdf_params: JSON.stringify(KDF_PARAMS) }
            }
        });
        const req = makeRequest('GET', '/api/auth/params?email=test@example.com') as any;

        const res = await handleAuthParams(req, env, mockCtx);
        const body = await res.json() as any;
        expect(body.authVersion).toBe(2);
        expect(body.kdfSalt).toBe('c'.repeat(32));
        expect(body.kdfParams).toEqual(KDF_PARAMS);
    });

    it('signals the legacy flow for an account that has not upgraded', async () => {
        const env = baseEnv({
            'SELECT auth_version': { first: { auth_version: 1, kdf_salt: null, kdf_params: null } }
        });
        const req = makeRequest('GET', '/api/auth/params?email=old@example.com') as any;

        const body = await (await handleAuthParams(req, env, mockCtx)).json() as any;
        expect(body.authVersion).toBe(1);
    });

    it('is not an account-existence oracle — unknown emails get plausible decoys', async () => {
        // Same status, same shape, same field set as a real answer. The only way
        // to tell them apart would be to know the server secret.
        const env = baseEnv({ 'SELECT auth_version': { first: null } });
        const req = makeRequest('GET', '/api/auth/params?email=nobody@example.com') as any;

        const res = await handleAuthParams(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.authVersion).toBe(2);
        expect(body.kdfSalt).toMatch(/^[0-9a-f]{32}$/);
        expect(body.kdfParams).toEqual(KDF_PARAMS);
    });

    it('returns a stable decoy for the same unknown email', async () => {
        // An unstable decoy would leak: a real account's salt never changes, so
        // a salt that differs between two calls marks the account as absent.
        const env = baseEnv({ 'SELECT auth_version': { first: null } });
        const one = await (await handleAuthParams(
            makeRequest('GET', '/api/auth/params?email=ghost@example.com') as any, env, mockCtx)).json() as any;
        const two = await (await handleAuthParams(
            makeRequest('GET', '/api/auth/params?email=ghost@example.com') as any, env, mockCtx)).json() as any;
        expect(one.kdfSalt).toBe(two.kdfSalt);
    });

    it('returns different decoys for different unknown emails', async () => {
        const env = baseEnv({ 'SELECT auth_version': { first: null } });
        const a = await (await handleAuthParams(
            makeRequest('GET', '/api/auth/params?email=a@example.com') as any, env, mockCtx)).json() as any;
        const b = await (await handleAuthParams(
            makeRequest('GET', '/api/auth/params?email=b@example.com') as any, env, mockCtx)).json() as any;
        expect(a.kdfSalt).not.toBe(b.kdfSalt);
    });

    it('answers a malformed email with a decoy rather than an error', async () => {
        const env = baseEnv({ 'SELECT auth_version': { first: null } });
        const res = await handleAuthParams(
            makeRequest('GET', '/api/auth/params?email=not-an-email') as any, env, mockCtx);
        expect(res.status).toBe(200);
        expect((await res.json() as any).authVersion).toBe(2);
    });

    it('rate limits by IP', async () => {
        const kv = createMockKV();
        (kv as any).get = vi.fn(() => Promise.resolve('999'));
        const env = baseEnv();
        (env as any).RATE_LIMIT = kv;

        const res = await handleAuthParams(
            makeRequest('GET', '/api/auth/params?email=test@example.com') as any, env, mockCtx);
        expect(res.status).toBe(429);
    });
});

// --- handleRegister ---

describe('handleRegister', () => {
    it('registers a new user successfully', async () => {
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        const req = makeRequest('POST', '/api/register', V2_REGISTRATION) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(201);
        const body = await res.json() as any;
        expect(body.message).toMatch(/registered/i);
    });

    it('rejects the legacy payload shape — no new account may use auth_version 1', async () => {
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        const req = makeRequest('POST', '/api/register', {
            email: 'test@example.com',
            masterPassword: 'Password123!',
            encryptionSalt: 'aabbcc',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(400);
    });

    it('normalises the email before checking for duplicates', async () => {
        const env = baseEnv({ 'SELECT id FROM users': { first: { id: 1 } } });
        const req = makeRequest('POST', '/api/register',
            { ...V2_REGISTRATION, email: '  TEST@Example.COM ' }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(409);
        const bind = (env.DB.prepare as any).mock.results[0].value.bind;
        expect(bind).toHaveBeenCalledWith('test@example.com');
    });

    it('rejects a syntactically invalid email', async () => {
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        const req = makeRequest('POST', '/api/register',
            { ...V2_REGISTRATION, email: 'not an email' }) as any;

        expect((await handleRegister(req, env, mockCtx)).status).toBe(400);
    });

    it('rejects Argon2id parameters below the safe floor', async () => {
        // A client that could talk the server into m=8 would be storing a
        // verifier derived from an effectively unstretched password.
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        const req = makeRequest('POST', '/api/register',
            { ...V2_REGISTRATION, kdfParams: { m: 8, t: 1, p: 1, len: 32 } }) as any;

        expect((await handleRegister(req, env, mockCtx)).status).toBe(400);
    });

    it('returns 409 when email already exists', async () => {
        const env = baseEnv({ 'SELECT id FROM users': { first: { id: 1 } } });
        const req = makeRequest('POST', '/api/register',
            { ...V2_REGISTRATION, email: 'existing@example.com' }) as any;

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
        const { turnstileToken, ...noToken } = V2_REGISTRATION;
        const req = makeRequest('POST', '/api/register', noToken) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(403);
        const body = await res.json() as any;
        expect(body.message).toMatch(/captcha/i);
    });

    it('returns 403 when Turnstile verification fails', async () => {
        mockTurnstileResponse(false);
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        const req = makeRequest('POST', '/api/register',
            { ...V2_REGISTRATION, turnstileToken: 'bad-token' }) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 429 after 5 failed register attempts from the same IP', async () => {
        const kv = createMockKV();
        (kv as any).get = vi.fn(() => Promise.resolve('5'));
        const env = baseEnv({ 'SELECT id FROM users': { first: null } });
        (env as any).RATE_LIMIT = kv;

        const req = makeRequest('POST', '/api/register', V2_REGISTRATION) as any;

        const res = await handleRegister(req, env, mockCtx);
        expect(res.status).toBe(429);
    });
});

// --- handleLogin ---

describe('handleLogin', () => {
    const v2User = {
        id: 1,
        email: 'test@example.com',
        password_hash: MOCK_HASH,
        password_salt: 'mocksalt',
        encryption_salt: '',
        auth_version: 2,
        legacy_vaults_pending: 0,
        totp_enabled: null
    };
    const v1User = { ...v2User, auth_version: 1, encryption_salt: 'encryptionsalt' };

    it('logs in a v2 account with an auth secret and returns its wrapped keys', async () => {
        const env = baseEnv({
            'LEFT JOIN user_totp': { first: v2User },
            'SELECT public_key': { first: { public_key: 'PUBKEY', private_key_enc: 'iv:ct' } }
        });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            authSecret: 'a'.repeat(64),
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.token).toBeTruthy();
        expect(body.authVersion).toBe(2);
        expect(body.publicKey).toBe('PUBKEY');
        expect(body.privateKeyEnc).toBe('iv:ct');
        // Nothing that could derive a vault key comes back for a migrated account.
        expect(body.encryptionSalt).toBeUndefined();
    });

    it('still accepts the legacy flow for an account that has not upgraded', async () => {
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: v1User } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            masterPassword: 'correct-password',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.authVersion).toBe(1);
        // The client needs this to decrypt its vaults one last time and upgrade.
        expect(body.encryptionSalt).toBe('encryptionsalt');
    });

    it('refuses a plaintext password for an already-upgraded account', async () => {
        // Otherwise an attacker could force a v2 user back onto the legacy path.
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: v2User } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            masterPassword: 'correct-password',
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        expect((await handleLogin(req, env, mockCtx)).status).toBe(401);
    });

    it('refuses an auth secret for an account still on the legacy flow', async () => {
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: v1User } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            authSecret: 'a'.repeat(64),
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        expect((await handleLogin(req, env, mockCtx)).status).toBe(401);
    });

    it('returns the legacy salt to a v2 account that still has org vaults to rescue', async () => {
        const env = baseEnv({
            'LEFT JOIN user_totp': { first: { ...v2User, legacy_vaults_pending: 2, encryption_salt: 'oldsalt' } },
            'SELECT public_key': { first: { public_key: 'PUBKEY', private_key_enc: 'iv:ct' } }
        });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            authSecret: 'a'.repeat(64),
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const body = await (await handleLogin(req, env, mockCtx)).json() as any;
        expect(body.legacyVaultsPending).toBe(2);
        expect(body.encryptionSalt).toBe('oldsalt');
    });

    it('withholds the session and returns a 2FA challenge when TOTP is enabled', async () => {
        // The LEFT JOIN surfaces totp_enabled=1, so handleLogin must NOT issue a
        // session token or leak key material — only a short-lived temp token.
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: { ...v2User, totp_enabled: 1 } } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            authSecret: 'a'.repeat(64),
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.requires2FA).toBe(true);
        expect(body.tempToken).toBeTruthy();
        expect(body.token).toBeUndefined();
        expect(body.privateKeyEnc).toBeUndefined();
        expect(body.encryptionSalt).toBeUndefined();

        // The temp token is scoped to '2fa' and carries `sub`, not `userId`.
        const decoded = decode(body.tempToken) as any;
        expect(decoded.scope).toBe('2fa');
        expect(decoded.sub).toBe(v2User.id);
        expect(decoded.userId).toBeUndefined();
    });

    it('returns 401 when user is not found', async () => {
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: null } });
        const req = makeRequest('POST', '/api/login', {
            email: 'nobody@example.com',
            authSecret: 'a'.repeat(64),
            turnstileToken: VALID_TURNSTILE_TOKEN
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('returns 401 when the verifier does not match', async () => {
        const env = baseEnv({
            'LEFT JOIN user_totp': { first: { ...v2User, password_hash: 'f'.repeat(32) } }
        });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            authSecret: 'a'.repeat(64),
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
            authSecret: 'a'.repeat(64),
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
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: v2User } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            authSecret: 'a'.repeat(64)
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(403);
        const body = await res.json() as any;
        expect(body.message).toMatch(/captcha/i);
    });

    it('returns 403 when Turnstile verification fails', async () => {
        mockTurnstileResponse(false);
        const env = baseEnv({ 'LEFT JOIN user_totp': { first: v2User } });
        const req = makeRequest('POST', '/api/login', {
            email: 'test@example.com',
            authSecret: 'a'.repeat(64),
            turnstileToken: 'bad-token'
        }) as any;

        const res = await handleLogin(req, env, mockCtx);
        expect(res.status).toBe(403);
    });
});

// --- handleAuthUpgrade ---

describe('handleAuthUpgrade', () => {
    const UPGRADE = {
        authSecret: 'a'.repeat(64),
        kdfSalt: 'b'.repeat(32),
        kdfParams: KDF_PARAMS,
        publicKey: 'PUBKEY',
        privateKeyEnc: 'iv:ct',
        vaults: [{ vaultId: 7, wrappedKey: 'iv:ct', ephemeralPubkey: 'EPH' }]
    };

    function upgradeEnv(extra = {}) {
        return baseEnv({
            'SELECT id, auth_version': { first: { id: 1, auth_version: 1 } },
            "SELECT id FROM vaults WHERE owner_id": { all: [{ id: 7 }] },
            'SELECT COUNT(*) AS cnt': { first: { cnt: 0 } },
            ...extra
        });
    }

    function upgradeReq(body: unknown = UPGRADE) {
        const req = makeRequest('POST', '/api/auth/upgrade', body) as any;
        req.user = { userId: 1, email: 'test@example.com' };
        return req;
    }

    it('upgrades a legacy account and reports what it re-keyed', async () => {
        const env = upgradeEnv();
        const res = await handleAuthUpgrade(upgradeReq(), env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.authVersion).toBe(2);
    });

    it('applies everything in a single batch, so it cannot partially land', async () => {
        // This is the property that makes the migration safe on live data: the
        // credentials, the keypair, the key shares and the vault key-version
        // flips are one transaction. A failure leaves the account wholly on v1
        // with its original blobs still live.
        const env = upgradeEnv();
        await handleAuthUpgrade(upgradeReq(), env, mockCtx);

        expect(env.DB.batch).toHaveBeenCalledTimes(1);
        const statements = (env.DB.batch as any).mock.calls[0][0];
        // user_keys + (share + version flip per vault) + users update
        expect(statements).toHaveLength(1 + 2 * UPGRADE.vaults.length + 1);
    });

    it('is idempotent — re-running on an upgraded account changes nothing', async () => {
        const env = upgradeEnv({ 'SELECT id, auth_version': { first: { id: 1, auth_version: 2 } } });
        const res = await handleAuthUpgrade(upgradeReq(), env, mockCtx);

        expect(res.status).toBe(200);
        expect((await res.json() as any).alreadyUpgraded).toBe(true);
        expect(env.DB.batch).not.toHaveBeenCalled();
    });

    it('refuses to re-key a vault the caller does not own', async () => {
        // Re-keying an org vault during the upgrade would make it unreadable to
        // every other member.
        const env = upgradeEnv({ "SELECT id FROM vaults WHERE owner_id": { all: [{ id: 99 }] } });
        const res = await handleAuthUpgrade(upgradeReq(), env, mockCtx);

        expect(res.status).toBe(403);
        expect(env.DB.batch).not.toHaveBeenCalled();
    });

    it('rejects an incomplete payload before writing anything', async () => {
        const env = upgradeEnv();
        const { publicKey, ...incomplete } = UPGRADE;
        const res = await handleAuthUpgrade(upgradeReq(incomplete), env, mockCtx);

        expect(res.status).toBe(400);
        expect(env.DB.batch).not.toHaveBeenCalled();
    });

    it('rejects a malformed key share', async () => {
        const env = upgradeEnv();
        const res = await handleAuthUpgrade(upgradeReq({
            ...UPGRADE,
            vaults: [{ vaultId: 'seven', wrappedKey: 'iv:ct', ephemeralPubkey: 'EPH' }]
        }), env, mockCtx);

        expect(res.status).toBe(400);
        expect(env.DB.batch).not.toHaveBeenCalled();
    });

    it('counts organisation vaults left on the legacy key as pending', async () => {
        // They can only be rescued by their creator, so they are deliberately
        // not migrated here — but the count keeps encryption_salt alive until
        // they are (#69).
        const env = upgradeEnv({ 'SELECT COUNT(*) AS cnt': { first: { cnt: 3 } } });
        const body = await (await handleAuthUpgrade(upgradeReq(), env, mockCtx)).json() as any;
        expect(body.legacyVaultsPending).toBe(3);
    });
});

// --- handleGetUserEncryptionSalt ---

describe('handleGetUserEncryptionSalt', () => {
    it('returns the encryption salt for the authenticated user', async () => {
        const env = baseEnv({
            'SELECT encryption_salt': { first: { encryption_salt: 'mysalt', legacy_vaults_pending: 1 } }
        });
        const req = makeRequest('GET', '/api/users/1/encryption-salt') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '1' };

        const res = await handleGetUserEncryptionSalt(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.encryptionSalt).toBe('mysalt');
    });

    it('reports null once the last legacy vault has been re-keyed', async () => {
        const env = baseEnv({
            'SELECT encryption_salt': { first: { encryption_salt: '', legacy_vaults_pending: 0 } }
        });
        const req = makeRequest('GET', '/api/users/1/encryption-salt') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '1' };

        const body = await (await handleGetUserEncryptionSalt(req, env, mockCtx)).json() as any;
        expect(body.encryptionSalt).toBeNull();
    });

    it('returns 403 when user ID does not match token', async () => {
        const env = baseEnv();
        const req = makeRequest('GET', '/api/users/2/encryption-salt') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '2' };

        const res = await handleGetUserEncryptionSalt(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('rejects a non-numeric user ID rather than coercing it', async () => {
        const env = baseEnv();
        const req = makeRequest('GET', '/api/users/1abc/encryption-salt') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '1abc' };

        expect((await handleGetUserEncryptionSalt(req, env, mockCtx)).status).toBe(403);
    });
});

// --- handleGetUserPublicKey ---

describe('handleGetUserPublicKey', () => {
    it('returns your own public key', async () => {
        const env = baseEnv({ 'SELECT public_key': { first: { public_key: 'MYKEY' } } });
        const req = makeRequest('GET', '/api/users/1/public-key') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '1' };

        const body = await (await handleGetUserPublicKey(req, env, mockCtx)).json() as any;
        expect(body.publicKey).toBe('MYKEY');
    });

    it('returns another user\'s key only when you share an organisation', async () => {
        const env = baseEnv({
            'JOIN user_organizations b': { first: { ok: 1 } },
            'SELECT public_key': { first: { public_key: 'THEIRKEY' } }
        });
        const req = makeRequest('GET', '/api/users/2/public-key') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '2' };

        const body = await (await handleGetUserPublicKey(req, env, mockCtx)).json() as any;
        expect(body.publicKey).toBe('THEIRKEY');
    });

    it('404s for an unrelated user rather than confirming they exist', async () => {
        const env = baseEnv({ 'JOIN user_organizations b': { first: null } });
        const req = makeRequest('GET', '/api/users/2/public-key') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '2' };

        expect((await handleGetUserPublicKey(req, env, mockCtx)).status).toBe(404);
    });

    it('distinguishes "not upgraded yet" from "no such user"', async () => {
        // The caller needs this to explain why sharing is not possible yet.
        const env = baseEnv({
            'JOIN user_organizations b': { first: { ok: 1 } },
            'SELECT public_key': { first: null }
        });
        const req = makeRequest('GET', '/api/users/2/public-key') as any;
        req.user = { userId: 1, email: 'a@b.com' };
        req.params = { userId: '2' };

        const res = await handleGetUserPublicKey(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.publicKey).toBeNull();
        expect(body.reason).toBe('not_upgraded');
    });
});

// --- handleUpdateMasterPassword ---

describe('handleUpdateMasterPassword', () => {
    const mockUser = { id: 1, password_hash: MOCK_HASH, password_salt: 'mocksalt', auth_version: 2 };
    const PAYLOAD = {
        oldAuthSecret: 'a'.repeat(64),
        newAuthSecret: 'c'.repeat(64),
        newKdfSalt: 'd'.repeat(32),
        newKdfParams: KDF_PARAMS,
        newPrivateKeyEnc: 'iv:ct'
    };

    function req(body: unknown = PAYLOAD, userId = '1') {
        const r = makeRequest('PUT', `/api/users/${userId}/update-password`, body) as any;
        r.user = { userId: 1 };
        r.params = { userId };
        return r;
    }

    it('updates the master password successfully', async () => {
        const env = baseEnv({ 'SELECT id, password_hash': { first: mockUser } });
        const res = await handleUpdateMasterPassword(req(), env, mockCtx);
        expect(res.status).toBe(200);
    });

    it('never touches vault ciphertext — only the verifier and the wrapped key', async () => {
        // This is what makes #70 unreachable for upgraded accounts: there is no
        // window where R2 and D1 disagree, because R2 is not written at all.
        const env = baseEnv({ 'SELECT id, password_hash': { first: mockUser } });
        await handleUpdateMasterPassword(req(), env, mockCtx);

        expect(env.VAULTS.put).not.toHaveBeenCalled();
        expect(env.DB.batch).toHaveBeenCalledTimes(1);
        expect((env.DB.batch as any).mock.calls[0][0]).toHaveLength(2);
    });

    it('returns 401 when old password is wrong', async () => {
        const env = baseEnv({
            'SELECT id, password_hash': { first: { ...mockUser, password_hash: 'f'.repeat(32) } }
        });
        const res = await handleUpdateMasterPassword(req(), env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('tells a not-yet-upgraded account to sign in again first', async () => {
        const env = baseEnv({ 'SELECT id, password_hash': { first: { ...mockUser, auth_version: 1 } } });
        const res = await handleUpdateMasterPassword(req(), env, mockCtx);
        expect(res.status).toBe(409);
    });

    it('returns 403 when user ID does not match token', async () => {
        const env = baseEnv();
        const res = await handleUpdateMasterPassword(req(PAYLOAD, '99'), env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 400 when fields are missing', async () => {
        const env = baseEnv();
        const res = await handleUpdateMasterPassword(req({ oldAuthSecret: 'a'.repeat(64) }), env, mockCtx);
        expect(res.status).toBe(400);
    });
});
