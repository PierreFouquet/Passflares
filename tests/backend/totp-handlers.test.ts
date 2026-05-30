// Handler tests for the 2FA flows: enable, disable, change authenticator, the
// recovery-code lifecycle, and the second login step. Uses a stateful in-memory
// D1/KV mock so multi-step flows (consume a code, then reuse it) behave like
// production.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { sign } from 'jsonwebtoken';
import { TOTP, Secret } from 'otpauth';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));
// scrypt is slow; the master-password check only needs deterministic equality.
vi.mock('../../src/utils.js', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../src/utils.js')>();
    return {
        ...actual,
        deriveScryptHash: vi.fn(async (pw: string, salt?: string | null) => ({
            hash: `hash:${pw}`,
            salt: salt ?? 'salt'
        }))
    };
});

import {
    handleTotpEnroll,
    handleTotpEnable,
    handleTotpDisable,
    handleRegenerateRecoveryCodes,
    handleTotpStatus,
    handleLoginVerify2fa,
    __testables
} from '../../src/totp.js';
import { createMockKV, mockCtx } from '../mocks/cloudflare.js';

const SECRET = 'test-jwt-secret-32-chars-minimum!!';
const ENC_KEY = 'handler-test-totp-enc-key-32-chars!!';
const CORRECT_PW = 'correct-horse-battery';

function code(base32: string): string {
    return new TOTP({ secret: Secret.fromBase32(base32), digits: 6, period: 30, algorithm: 'SHA1' }).generate();
}

// ── Stateful D1 mock tailored to the queries in src/totp.ts ──────────────────
interface World {
    user: { id: number; email: string; password_hash: string; password_salt: string; encryption_salt: string } | null;
    totp: { user_id: number; secret_enc: string | null; pending_secret_enc: string | null; enabled: number; confirmed_at: string | null } | null;
    recovery: { id: number; user_id: number; code_hash: string; used_at: string | null }[];
    nextRecoveryId: number;
}

function makeDB(world: World) {
    const stmt = (sql: string) => ({
        bind: (...args: any[]) => ({
            first: async () => {
                if (sql.includes('FROM user_totp WHERE user_id')) return world.totp;
                if (sql.includes('password_hash, password_salt FROM users')) {
                    return world.user ? { password_hash: world.user.password_hash, password_salt: world.user.password_salt } : null;
                }
                if (sql.includes('encryption_salt FROM users')) {
                    return world.user ? { id: world.user.id, email: world.user.email, encryption_salt: world.user.encryption_salt } : null;
                }
                if (sql.includes('COUNT(*) AS cnt FROM user_recovery_codes')) {
                    return { cnt: world.recovery.filter(r => r.used_at === null).length };
                }
                if (sql.includes('SELECT id FROM user_recovery_codes')) {
                    const hash = args[1];
                    const row = world.recovery.find(r => r.code_hash === hash && r.used_at === null);
                    return row ? { id: row.id } : null;
                }
                return null;
            },
            run: async () => {
                if (sql.startsWith('INSERT INTO user_totp')) {
                    world.totp = { user_id: args[0], secret_enc: world.totp?.secret_enc ?? null, pending_secret_enc: args[1], enabled: world.totp?.enabled ?? 0, confirmed_at: world.totp?.confirmed_at ?? null };
                } else if (sql.includes('UPDATE user_totp SET secret_enc = pending_secret_enc')) {
                    if (world.totp) { world.totp.secret_enc = world.totp.pending_secret_enc; world.totp.pending_secret_enc = null; world.totp.enabled = 1; world.totp.confirmed_at = 'now'; }
                } else if (sql.includes('DELETE FROM user_recovery_codes')) {
                    world.recovery = [];
                } else if (sql.includes('DELETE FROM user_totp')) {
                    world.totp = null;
                } else if (sql.includes('UPDATE user_recovery_codes SET used_at')) {
                    const row = world.recovery.find(r => r.id === args[0]);
                    if (row) row.used_at = 'now';
                }
                return { success: true, meta: {} };
            },
            all: async () => ({ results: [], success: true })
        })
    });
    return {
        prepare: (sql: string) => stmt(sql),
        batch: async (stmts: any[]) => {
            // recovery-code inserts are batched: bind(userId, hash)
            for (const s of stmts) {
                if (s.__insert) world.recovery.push({ id: world.nextRecoveryId++, user_id: s.__args[0], code_hash: s.__args[1], used_at: null });
            }
            return [];
        }
    } as unknown as D1Database;
}

// The batch path needs the prepared INSERT to remember its bound args. Patch
// prepare() so an INSERT into user_recovery_codes records them for batch().
function makeDBWithBatch(world: World) {
    const db = makeDB(world) as any;
    const origPrepare = db.prepare.bind(db);
    db.prepare = (sql: string) => {
        if (sql.startsWith('INSERT INTO user_recovery_codes')) {
            return { bind: (...a: any[]) => ({ __insert: true, __args: a }) };
        }
        return origPrepare(sql);
    };
    return db as D1Database;
}

function makeEnv(world: World, kv = createMockKV()) {
    return {
        DB: makeDBWithBatch(world),
        RATE_LIMIT: kv,
        JWT_SECRET: SECRET,
        TOTP_ENC_KEY: ENC_KEY
    } as any;
}

function authedReq(userId: number, email: string, body: any) {
    const req: any = new Request('https://passflares.test/api/2fa/x', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    req.user = { userId, email, iat: 0, exp: 9999999999 };
    return req;
}

function freshWorld(): World {
    return {
        user: { id: 1, email: 'u@example.com', password_hash: `hash:${CORRECT_PW}`, password_salt: 'salt', encryption_salt: 'enc-salt' },
        totp: null,
        recovery: [],
        nextRecoveryId: 1
    };
}

// Drives enroll → enable, returning the active secret + issued recovery codes.
async function enableFresh(world: World, env: any) {
    const enroll = await handleTotpEnroll(authedReq(1, 'u@example.com', {}), env, mockCtx);
    const { secret } = await enroll.json() as any;
    const enable = await handleTotpEnable(authedReq(1, 'u@example.com', { code: code(secret) }), env, mockCtx);
    const body = await enable.json() as any;
    return { secret, recoveryCodes: body.recoveryCodes as string[] };
}

beforeEach(() => vi.clearAllMocks());

describe('Adding 2FA (enroll → enable)', () => {
    it('enroll returns a secret + QR and creates a pending (not enabled) row', async () => {
        const world = freshWorld();
        const res = await handleTotpEnroll(authedReq(1, 'u@example.com', {}), makeEnv(world), mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.secret).toBeTruthy();
        expect(body.qrDataUri.startsWith('data:image/svg+xml')).toBe(true);
        expect(world.totp?.enabled).toBe(0);
        expect(world.totp?.pending_secret_enc).toBeTruthy();
    });

    it('enable with a valid code flips enabled and returns 10 recovery codes', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { recoveryCodes } = await enableFresh(world, env);
        expect(world.totp?.enabled).toBe(1);
        expect(world.totp?.secret_enc).toBeTruthy();
        expect(world.totp?.pending_secret_enc).toBeNull();
        expect(recoveryCodes).toHaveLength(__testables.RECOVERY_CODE_COUNT);
        expect(world.recovery.filter(r => r.used_at === null)).toHaveLength(__testables.RECOVERY_CODE_COUNT);
    });

    it('enable with an invalid code returns 401 and does not enable', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        await handleTotpEnroll(authedReq(1, 'u@example.com', {}), env, mockCtx);
        const res = await handleTotpEnable(authedReq(1, 'u@example.com', { code: '000000' }), env, mockCtx);
        expect(res.status).toBe(401);
        expect(world.totp?.enabled).toBe(0);
    });

    it('enable with no enrollment in progress returns 400', async () => {
        const world = freshWorld();
        const res = await handleTotpEnable(authedReq(1, 'u@example.com', { code: '123456' }), makeEnv(world), mockCtx);
        expect(res.status).toBe(400);
    });
});

describe('Removing 2FA (disable)', () => {
    it('requires master password + a current code', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { secret } = await enableFresh(world, env);
        const res = await handleTotpDisable(authedReq(1, 'u@example.com', { masterPassword: 'wrong', code: code(secret) }), env, mockCtx);
        expect(res.status).toBe(401);
        expect(world.totp).not.toBeNull();
    });

    it('disables and clears secret + recovery codes with valid credentials', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { secret } = await enableFresh(world, env);
        const res = await handleTotpDisable(authedReq(1, 'u@example.com', { masterPassword: CORRECT_PW, code: code(secret) }), env, mockCtx);
        expect(res.status).toBe(200);
        expect(world.totp).toBeNull();
        expect(world.recovery).toHaveLength(0);
    });

    it('can be disabled using a recovery code instead of a TOTP code', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { recoveryCodes } = await enableFresh(world, env);
        const res = await handleTotpDisable(authedReq(1, 'u@example.com', { masterPassword: CORRECT_PW, code: recoveryCodes[0] }), env, mockCtx);
        expect(res.status).toBe(200);
        expect(world.totp).toBeNull();
    });
});

describe('Changing authenticator (enroll while enabled → enable)', () => {
    it('requires re-auth (password + current code) to start the change', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { secret } = await enableFresh(world, env);
        const res = await handleTotpEnroll(authedReq(1, 'u@example.com', { masterPassword: 'wrong', code: code(secret) }), env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('keeps the old secret valid until the new one is confirmed', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { secret: oldSecret } = await enableFresh(world, env);

        const enroll = await handleTotpEnroll(authedReq(1, 'u@example.com', { masterPassword: CORRECT_PW, code: code(oldSecret) }), env, mockCtx);
        const { secret: newSecret } = await enroll.json() as any;
        // Old secret is still active until confirm.
        expect(world.totp?.enabled).toBe(1);
        expect(newSecret).not.toBe(oldSecret);

        const enable = await handleTotpEnable(authedReq(1, 'u@example.com', { code: code(newSecret) }), env, mockCtx);
        const body = await enable.json() as any;
        expect(body.changed).toBe(true);
        // No new recovery codes on a change.
        expect(body.recoveryCodes).toBeUndefined();
    });

    it('after change, the new secret verifies on login and the old one does not', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { secret: oldSecret } = await enableFresh(world, env);
        const enroll = await handleTotpEnroll(authedReq(1, 'u@example.com', { masterPassword: CORRECT_PW, code: code(oldSecret) }), env, mockCtx);
        const { secret: newSecret } = await enroll.json() as any;
        await handleTotpEnable(authedReq(1, 'u@example.com', { code: code(newSecret) }), env, mockCtx);

        const temp = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const okNew = await handleLoginVerify2fa(loginReq({ tempToken: temp, code: code(newSecret) }), env, mockCtx);
        expect(okNew.status).toBe(200);

        const temp2 = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const badOld = await handleLoginVerify2fa(loginReq({ tempToken: temp2, code: code(oldSecret) }), env, mockCtx);
        expect(badOld.status).toBe(401);
    });
});

describe('Recovery code lifecycle', () => {
    it('regenerate requires the master password and replaces the set', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { recoveryCodes: first } = await enableFresh(world, env);

        const bad = await handleRegenerateRecoveryCodes(authedReq(1, 'u@example.com', { masterPassword: 'nope' }), env, mockCtx);
        expect(bad.status).toBe(401);

        const res = await handleRegenerateRecoveryCodes(authedReq(1, 'u@example.com', { masterPassword: CORRECT_PW }), env, mockCtx);
        const body = await res.json() as any;
        expect(body.recoveryCodes).toHaveLength(__testables.RECOVERY_CODE_COUNT);
        // Old codes no longer present.
        const oldHash = __testables.hashRecoveryCode(env, first[0]);
        expect(world.recovery.some(r => r.code_hash === oldHash)).toBe(false);
    });

    it('status reflects remaining unused codes', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        await enableFresh(world, env);
        const res = await handleTotpStatus(authedReq(1, 'u@example.com', {}), env, mockCtx);
        const body = await res.json() as any;
        expect(body.enabled).toBe(true);
        expect(body.remainingRecoveryCodes).toBe(__testables.RECOVERY_CODE_COUNT);
    });
});

// ── second login step ────────────────────────────────────────────────────────
function loginReq(body: any) {
    return new Request('https://passflares.test/api/login/2fa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    }) as any;
}

describe('handleLoginVerify2fa', () => {
    it('valid temp token + TOTP returns a full session', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { secret } = await enableFresh(world, env);
        const temp = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const res = await handleLoginVerify2fa(loginReq({ tempToken: temp, code: code(secret) }), env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.token).toBeTruthy();
        expect(body.encryptionSalt).toBe('enc-salt');
    });

    it('consumes a recovery code (works once, rejected on reuse)', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { recoveryCodes } = await enableFresh(world, env);

        const t1 = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const r1 = await handleLoginVerify2fa(loginReq({ tempToken: t1, code: recoveryCodes[0] }), env, mockCtx);
        expect(r1.status).toBe(200);
        const b1 = await r1.json() as any;
        expect(b1.recoveryCodeUsed).toBe(true);
        expect(b1.remainingRecoveryCodes).toBe(__testables.RECOVERY_CODE_COUNT - 1);

        const t2 = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const r2 = await handleLoginVerify2fa(loginReq({ tempToken: t2, code: recoveryCodes[0] }), env, mockCtx);
        expect(r2.status).toBe(401);
    });

    it('rejects a non-2fa-scoped token (a real session token)', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const { secret } = await enableFresh(world, env);
        const sessionToken = sign({ userId: 1, email: 'u@example.com' }, SECRET, { expiresIn: '1h' });
        const res = await handleLoginVerify2fa(loginReq({ tempToken: sessionToken, code: code(secret) }), env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('rejects an expired/invalid temp token', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        await enableFresh(world, env);
        const expired = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '-1s' });
        const res = await handleLoginVerify2fa(loginReq({ tempToken: expired, code: '123456' }), env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('rate-limits after repeated failures from one IP', async () => {
        const world = freshWorld();
        const kv = createMockKV();
        (kv as any).get = vi.fn(async () => '5');
        const env = makeEnv(world, kv);
        await enableFresh(world, env);
        const temp = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const res = await handleLoginVerify2fa(loginReq({ tempToken: temp, code: '000000' }), env, mockCtx);
        expect(res.status).toBe(429);
    });

    it('returns 400 when the code is missing', async () => {
        const world = freshWorld();
        const env = makeEnv(world);
        const temp = sign({ sub: 1, email: 'u@example.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const res = await handleLoginVerify2fa(loginReq({ tempToken: temp }), env, mockCtx);
        expect(res.status).toBe(400);
    });
});
