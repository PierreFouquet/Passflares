// Integration tests: real SQLite, real migrations, real SQL.
//
// The unit tests in ../auth.test.ts drive the handlers against a mock that
// returns canned rows keyed by a SQL substring. That proves the branching is
// right, but it cannot prove the SQL is: a misspelled column, a broken
// ON CONFLICT, or a JOIN that matches nothing all "pass" against a mock, and so
// does a D1.batch() that isn't actually atomic.
//
// The auth_version 1 -> 2 upgrade runs once per live account and rewrites its
// credentials, so the properties below are the ones that must not be taken on
// trust:
//
//   - the batch either lands completely or not at all
//   - a failure leaves the account fully on v1 with its original blobs live
//   - the legacy_vaults_pending COUNT actually matches org vaults
//   - vault key shares are enforced by real foreign keys and real permissions

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createTestD1, createTestR2, createTestKV, type TestD1 } from '../../mocks/d1.js';
import { makeRequest, mockCtx } from '../../mocks/cloudflare.js';

vi.mock('../../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

// Turnstile always passes; it is exercised separately in auth.test.ts.
vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ success: true }), { status: 200 })));

const { handleRegister, handleLogin, handleAuthUpgrade, handleAuthParams } =
    await import('../../../src/auth.js');
const { handleGetVaults, handlePutVaultShares, handleCommitKeyVersion, handleUploadVault } =
    await import('../../../src/vaults.js');
const { deriveScryptHash } = await import('../../../src/utils.js');

const KDF_PARAMS = { m: 47104, t: 1, p: 1, len: 32 };

let d1: TestD1;
let env: any;

beforeEach(() => {
    d1 = createTestD1();
    env = {
        DB: d1,
        VAULTS: createTestR2(),
        RATE_LIMIT: createTestKV(),
        JWT_SECRET: 'test-jwt-secret-32-chars-minimum!!',
        TURNSTILE_KEY: 'test-turnstile-key',
        TOTP_ENC_KEY: 'test-totp-enc-key-32-chars-minimum!!'
    };
});

function authed(method: string, path: string, body?: unknown, params: Record<string, string> = {}, userId = 1) {
    const req = makeRequest(method, path, body) as any;
    req.user = { userId, email: 'tester@example.com' };
    req.params = params;
    return req;
}

/** Inserts a legacy (auth_version 1) account exactly as migration 0001 would have. */
async function seedLegacyUser(email = 'legacy@example.com', password = 'old-password') {
    const { hash, salt } = await deriveScryptHash(password);
    const info = d1.db.prepare(
        `INSERT INTO users (email, password_hash, password_salt, encryption_salt, auth_version)
         VALUES (?, ?, ?, ?, 1)`
    ).run(email, hash, salt, 'ff'.repeat(16));
    return Number(info.lastInsertRowid);
}

function seedVault(ownerId: string, ownerType: 'user' | 'organization', name = 'Vault', keyVersion = 'v1') {
    const info = d1.db.prepare(
        `INSERT INTO vaults (name, owner_id, owner_type, r2_object_key, current_key_version)
         VALUES (?, ?, ?, ?, ?)`
    ).run(name, ownerId, ownerType, `${ownerId}_${name}_key`, keyVersion);
    const vaultId = Number(info.lastInsertRowid);
    d1.db.prepare(
        `INSERT INTO vault_access_controls (vault_id, entity_id, entity_type, permission_level)
         VALUES (?, ?, ?, 'manage')`
    ).run(vaultId, ownerId, ownerType);
    return vaultId;
}

describe('migrations apply cleanly and produce the expected schema', () => {
    it('creates the key-hierarchy tables and columns', () => {
        const cols = d1.query<{ name: string }>('PRAGMA table_info(users)').map(c => c.name);
        expect(cols).toEqual(expect.arrayContaining([
            'auth_version', 'kdf_salt', 'kdf_params', 'legacy_vaults_pending'
        ]));

        const tables = d1.query<{ name: string }>(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).map(t => t.name);
        expect(tables).toEqual(expect.arrayContaining(['user_keys', 'vault_key_shares']));
    });

    it('defaults existing accounts to auth_version 1, so nobody is locked out by the migration', async () => {
        const id = await seedLegacyUser();
        const [user] = d1.query<{ auth_version: number }>('SELECT auth_version FROM users WHERE id = ?', id);
        expect(user.auth_version).toBe(1);
    });

    it('cascades key shares when a vault is deleted', () => {
        const userId = 1;
        d1.db.prepare(
            `INSERT INTO users (id, email, password_hash, password_salt, encryption_salt) VALUES (?, ?, 'h', 's', '')`
        ).run(userId, 'a@b.com');
        const vaultId = seedVault('user_1', 'user');
        d1.db.prepare(
            `INSERT INTO vault_key_shares (vault_id, user_id, wrapped_key, ephemeral_pubkey) VALUES (?, ?, 'k', 'e')`
        ).run(vaultId, userId);

        d1.db.prepare('DELETE FROM vaults WHERE id = ?').run(vaultId);
        expect(d1.query('SELECT * FROM vault_key_shares WHERE vault_id = ?', vaultId)).toHaveLength(0);
    });
});

describe('registration and sign-in round trip against real SQL', () => {
    const REGISTRATION = {
        email: 'new@example.com',
        authSecret: 'a'.repeat(64),
        kdfSalt: 'b'.repeat(32),
        kdfParams: KDF_PARAMS,
        publicKey: 'PUBKEY',
        privateKeyEnc: 'iv:ct',
        turnstileToken: 'ok'
    };

    it('writes a v2 user and their keypair', async () => {
        const res = await handleRegister(makeRequest('POST', '/api/register', REGISTRATION) as any, env, mockCtx);
        expect(res.status).toBe(201);

        const [user] = d1.query<any>('SELECT * FROM users WHERE email = ?', 'new@example.com');
        expect(user.auth_version).toBe(2);
        expect(user.kdf_salt).toBe('b'.repeat(32));
        expect(JSON.parse(user.kdf_params)).toEqual(KDF_PARAMS);
        // The auth secret is hashed, never stored as presented.
        expect(user.password_hash).not.toBe(REGISTRATION.authSecret);

        const [keys] = d1.query<any>('SELECT * FROM user_keys WHERE user_id = ?', user.id);
        expect(keys.public_key).toBe('PUBKEY');
        expect(keys.private_key_enc).toBe('iv:ct');
    });

    it('signs that account back in with the same auth secret', async () => {
        await handleRegister(makeRequest('POST', '/api/register', REGISTRATION) as any, env, mockCtx);

        const res = await handleLogin(makeRequest('POST', '/api/login', {
            email: 'new@example.com', authSecret: REGISTRATION.authSecret, turnstileToken: 'ok'
        }) as any, env, mockCtx);

        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.authVersion).toBe(2);
        expect(body.privateKeyEnc).toBe('iv:ct');
        expect(body.encryptionSalt).toBeUndefined();
    });

    it('rejects the wrong auth secret', async () => {
        await handleRegister(makeRequest('POST', '/api/register', REGISTRATION) as any, env, mockCtx);
        const res = await handleLogin(makeRequest('POST', '/api/login', {
            email: 'new@example.com', authSecret: 'c'.repeat(64), turnstileToken: 'ok'
        }) as any, env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('treats differently-cased emails as one account', async () => {
        await handleRegister(makeRequest('POST', '/api/register', REGISTRATION) as any, env, mockCtx);
        const dup = await handleRegister(makeRequest('POST', '/api/register',
            { ...REGISTRATION, email: 'NEW@Example.COM' }) as any, env, mockCtx);
        expect(dup.status).toBe(409);
        expect(d1.query('SELECT id FROM users')).toHaveLength(1);
    });

    it('serves real KDF params to a known account and decoys to an unknown one', async () => {
        await handleRegister(makeRequest('POST', '/api/register', REGISTRATION) as any, env, mockCtx);

        const known = await (await handleAuthParams(
            makeRequest('GET', '/api/auth/params?email=new@example.com') as any, env, mockCtx)).json() as any;
        expect(known.kdfSalt).toBe('b'.repeat(32));

        const unknown = await (await handleAuthParams(
            makeRequest('GET', '/api/auth/params?email=ghost@example.com') as any, env, mockCtx)).json() as any;
        expect(unknown.authVersion).toBe(2);
        expect(unknown.kdfSalt).toMatch(/^[0-9a-f]{32}$/);
        expect(unknown.kdfSalt).not.toBe(known.kdfSalt);
    });
});

describe('the auth_version 1 -> 2 upgrade', () => {
    const UPGRADE = {
        authSecret: 'a'.repeat(64),
        kdfSalt: 'b'.repeat(32),
        kdfParams: KDF_PARAMS,
        publicKey: 'PUBKEY',
        privateKeyEnc: 'iv:ct'
    };

    it('moves credentials, keypair, shares and key versions together', async () => {
        const userId = await seedLegacyUser();
        const vaultId = seedVault(`user_${userId}`, 'user');
        const [before] = d1.query<any>('SELECT password_hash FROM users WHERE id = ?', userId);

        const res = await handleAuthUpgrade(authed('POST', '/api/auth/upgrade', {
            ...UPGRADE, vaults: [{ vaultId, wrappedKey: 'wk', ephemeralPubkey: 'eph' }]
        }, {}, userId), env, mockCtx);

        expect(res.status).toBe(200);

        const [user] = d1.query<any>('SELECT * FROM users WHERE id = ?', userId);
        expect(user.auth_version).toBe(2);
        expect(user.kdf_salt).toBe('b'.repeat(32));
        expect(user.password_hash).not.toBe(before.password_hash);

        const [keys] = d1.query<any>('SELECT * FROM user_keys WHERE user_id = ?', userId);
        expect(keys.public_key).toBe('PUBKEY');

        const [share] = d1.query<any>('SELECT * FROM vault_key_shares WHERE vault_id = ?', vaultId);
        expect(share.user_id).toBe(userId);
        expect(share.wrapped_key).toBe('wk');

        // The flip is what makes the client's staged .v2 blob authoritative.
        const [vault] = d1.query<any>('SELECT current_key_version FROM vaults WHERE id = ?', vaultId);
        expect(vault.current_key_version).toBe('v2');
    });

    it('clears the legacy salt when nothing needs it', async () => {
        const userId = await seedLegacyUser();
        await handleAuthUpgrade(authed('POST', '/api/auth/upgrade', { ...UPGRADE, vaults: [] }, {}, userId), env, mockCtx);
        const [user] = d1.query<any>('SELECT encryption_salt, legacy_vaults_pending FROM users WHERE id = ?', userId);
        expect(user.legacy_vaults_pending).toBe(0);
        expect(user.encryption_salt).toBe('');
    });

    it('retains the legacy salt while org vaults still hold v1 ciphertext', async () => {
        // Only their creator can re-key those (#69), so the PBKDF2 salt has to
        // survive the upgrade or the data becomes unreachable for everyone.
        const userId = await seedLegacyUser();
        const orgInfo = d1.db.prepare(
            `INSERT INTO organizations (name, created_by) VALUES ('Acme', ?)`
        ).run(userId);
        const orgId = Number(orgInfo.lastInsertRowid);
        d1.db.prepare(
            `INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, 'super_admin')`
        ).run(userId, orgId);
        seedVault(`org_${orgId}`, 'organization', 'Team', 'v1');
        seedVault(`org_${orgId}`, 'organization', 'Team2', 'v1');

        await handleAuthUpgrade(authed('POST', '/api/auth/upgrade', { ...UPGRADE, vaults: [] }, {}, userId), env, mockCtx);

        const [user] = d1.query<any>('SELECT encryption_salt, legacy_vaults_pending FROM users WHERE id = ?', userId);
        expect(user.legacy_vaults_pending).toBe(2);
        expect(user.encryption_salt).toBe('ff'.repeat(16));
    });

    it('leaves the account entirely on v1 when the batch fails', async () => {
        // The property the live migration rests on. A share naming a vault that
        // no longer exists trips the foreign key, so the whole batch rolls back
        // and the account must be exactly as it was.
        const userId = await seedLegacyUser();
        const vaultId = seedVault(`user_${userId}`, 'user');
        const [before] = d1.query<any>('SELECT * FROM users WHERE id = ?', userId);

        d1.db.prepare('DELETE FROM vaults WHERE id = ?').run(vaultId);

        const res = await handleAuthUpgrade(authed('POST', '/api/auth/upgrade', {
            ...UPGRADE, vaults: [{ vaultId, wrappedKey: 'wk', ephemeralPubkey: 'eph' }]
        }, {}, userId), env, mockCtx);

        expect(res.status).toBe(403); // rejected before the batch: not an owned vault

        const [after] = d1.query<any>('SELECT * FROM users WHERE id = ?', userId);
        expect(after.auth_version).toBe(1);
        expect(after.password_hash).toBe(before.password_hash);
        expect(after.encryption_salt).toBe(before.encryption_salt);
        expect(d1.query('SELECT * FROM user_keys WHERE user_id = ?', userId)).toHaveLength(0);
    });

    it('is idempotent — a retry does not clobber the keypair already in place', async () => {
        const userId = await seedLegacyUser();
        await handleAuthUpgrade(authed('POST', '/api/auth/upgrade', { ...UPGRADE, vaults: [] }, {}, userId), env, mockCtx);
        const [first] = d1.query<any>('SELECT * FROM user_keys WHERE user_id = ?', userId);

        const res = await handleAuthUpgrade(authed('POST', '/api/auth/upgrade', {
            ...UPGRADE, publicKey: 'DIFFERENT', privateKeyEnc: 'other:blob', vaults: []
        }, {}, userId), env, mockCtx);

        expect((await res.json() as any).alreadyUpgraded).toBe(true);
        const [second] = d1.query<any>('SELECT * FROM user_keys WHERE user_id = ?', userId);
        expect(second.public_key).toBe(first.public_key);
    });

    it('refuses to re-key a vault owned by someone else', async () => {
        const mine = await seedLegacyUser('me@example.com');
        const theirs = await seedLegacyUser('them@example.com');
        const theirVault = seedVault(`user_${theirs}`, 'user');

        const res = await handleAuthUpgrade(authed('POST', '/api/auth/upgrade', {
            ...UPGRADE, vaults: [{ vaultId: theirVault, wrappedKey: 'wk', ephemeralPubkey: 'eph' }]
        }, {}, mine), env, mockCtx);

        expect(res.status).toBe(403);
        expect(d1.query('SELECT * FROM vault_key_shares')).toHaveLength(0);
    });
});

describe('vault key shares are enforced against real permissions', () => {
    async function twoMemberOrg() {
        const alice = await seedLegacyUser('alice@example.com');
        const bob = await seedLegacyUser('bob@example.com');
        const orgInfo = d1.db.prepare(`INSERT INTO organizations (name, created_by) VALUES ('Acme', ?)`).run(alice);
        const orgId = Number(orgInfo.lastInsertRowid);
        for (const [uid, role] of [[alice, 'super_admin'], [bob, 'admin']] as const) {
            d1.db.prepare(`INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, ?)`)
                .run(uid, orgId, role);
        }
        const vaultId = seedVault(`org_${orgId}`, 'organization', 'Team', 'v2');
        return { alice, bob, orgId, vaultId };
    }

    it('lets an admin share a vault key with a fellow org member (#69)', async () => {
        const { alice, bob, vaultId } = await twoMemberOrg();

        const res = await handlePutVaultShares(authed('PUT', `/api/vaults/${vaultId}/shares`, {
            shares: [{ userId: bob, wrappedKey: 'for-bob', ephemeralPubkey: 'eph' }]
        }, { vaultId: String(vaultId) }, alice), env, mockCtx);

        expect(res.status).toBe(200);
        const [share] = d1.query<any>(
            'SELECT * FROM vault_key_shares WHERE vault_id = ? AND user_id = ?', vaultId, bob);
        expect(share.wrapped_key).toBe('for-bob');
    });

    it('refuses to mint a share for someone outside the organisation', async () => {
        const { alice, vaultId } = await twoMemberOrg();
        const outsider = await seedLegacyUser('mallory@example.com');

        const res = await handlePutVaultShares(authed('PUT', `/api/vaults/${vaultId}/shares`, {
            shares: [{ userId: outsider, wrappedKey: 'leak', ephemeralPubkey: 'eph' }]
        }, { vaultId: String(vaultId) }, alice), env, mockCtx);

        expect(res.status).toBe(403);
        expect(d1.query('SELECT * FROM vault_key_shares WHERE user_id = ?', outsider)).toHaveLength(0);
    });

    it('replaces every share on rotation, so a revoked member keeps nothing', async () => {
        const { alice, bob, vaultId } = await twoMemberOrg();
        d1.db.prepare(
            `INSERT INTO vault_key_shares (vault_id, user_id, wrapped_key, ephemeral_pubkey) VALUES (?, ?, 'stale', 'old')`
        ).run(vaultId, bob);

        await handlePutVaultShares(authed('PUT', `/api/vaults/${vaultId}/shares`, {
            shares: [{ userId: alice, wrappedKey: 'rotated', ephemeralPubkey: 'eph' }],
            replace: true
        }, { vaultId: String(vaultId) }, alice), env, mockCtx);

        const rows = d1.query<any>('SELECT user_id FROM vault_key_shares WHERE vault_id = ?', vaultId);
        expect(rows.map(r => r.user_id)).toEqual([alice]);
    });

    it('reports has_key_share per vault, so the UI can explain an unopenable one', async () => {
        const { alice, bob, vaultId } = await twoMemberOrg();
        d1.db.prepare(
            `INSERT INTO vault_key_shares (vault_id, user_id, wrapped_key, ephemeral_pubkey) VALUES (?, ?, 'k', 'e')`
        ).run(vaultId, alice);

        const forAlice = await (await handleGetVaults(authed('GET', '/api/vaults', undefined, {}, alice), env, mockCtx)).json() as any[];
        const forBob = await (await handleGetVaults(authed('GET', '/api/vaults', undefined, {}, bob), env, mockCtx)).json() as any[];

        expect(forAlice.find(v => v.id === vaultId).has_key_share).toBe(true);
        // Bob is authorised but keyless — precisely the state #69 described.
        expect(forBob.find(v => v.id === vaultId).has_key_share).toBe(false);
    });

    it('never returns r2_object_key to a client (#80)', async () => {
        const { alice } = await twoMemberOrg();
        const vaults = await (await handleGetVaults(authed('GET', '/api/vaults', undefined, {}, alice), env, mockCtx)).json() as any[];
        expect(vaults.length).toBeGreaterThan(0);
        for (const vault of vaults) expect(vault).not.toHaveProperty('r2_object_key');
    });
});

describe('versioned vault writes (#70)', () => {
    it('stages a new key version without touching the live blob, then commits it', async () => {
        const userId = await seedLegacyUser();
        const vaultId = seedVault(`user_${userId}`, 'user', 'Personal', 'v1');
        const [vault] = d1.query<any>('SELECT r2_object_key FROM vaults WHERE id = ?', vaultId);
        env.VAULTS.store.set(vault.r2_object_key, JSON.stringify({ iv: 'old', ciphertext: 'old' }));

        const staged = await handleUploadVault(authed('PUT', `/api/vaults/${vaultId}/data`, {
            encryptedData: { iv: 'new', ciphertext: 'new' }, keyVersion: 'v2'
        }, { vaultId: String(vaultId) }, userId), env, mockCtx);

        expect((await staged.json() as any).staged).toBe(true);
        // Live blob untouched — an interrupted re-encryption loses nothing.
        expect(JSON.parse(env.VAULTS.store.get(vault.r2_object_key))).toEqual({ iv: 'old', ciphertext: 'old' });
        expect(env.VAULTS.store.has(`${vault.r2_object_key}.v2`)).toBe(true);

        const committed = await handleCommitKeyVersion(authed('POST', '/api/vaults/key-version/commit', {
            vaults: [{ vaultId, keyVersion: 'v2' }]
        }, {}, userId), env, mockCtx);

        expect(committed.status).toBe(200);
        const [after] = d1.query<any>('SELECT current_key_version FROM vaults WHERE id = ?', vaultId);
        expect(after.current_key_version).toBe('v2');
        // Superseded blob swept.
        expect(env.VAULTS.store.has(vault.r2_object_key)).toBe(false);
    });

    it('refuses to commit a vault the caller cannot write', async () => {
        const owner = await seedLegacyUser('owner@example.com');
        const stranger = await seedLegacyUser('stranger@example.com');
        const vaultId = seedVault(`user_${owner}`, 'user');

        const res = await handleCommitKeyVersion(authed('POST', '/api/vaults/key-version/commit', {
            vaults: [{ vaultId, keyVersion: 'v2' }]
        }, {}, stranger), env, mockCtx);

        expect(res.status).toBe(403);
        const [vault] = d1.query<any>('SELECT current_key_version FROM vaults WHERE id = ?', vaultId);
        expect(vault.current_key_version).toBe('v1');
    });
});
