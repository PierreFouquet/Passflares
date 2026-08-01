// Versioned R2 writes (#70) and vault key shares (#69).
//
// These two mechanisms are what make re-encryption survivable and sharing
// possible. The properties worth pinning down are:
//
//   - a write under a new key version never destroys the live blob
//   - the version flip is atomic across every vault in the batch
//   - `manage` on a vault does not let you mint a key share for an outsider
//   - r2_object_key never reaches a client

import { describe, it, expect, vi } from 'vitest';
import {
    handleCreateVault,
    handleGetVaults,
    handleUploadVault,
    handleDownloadVault,
    handleDeleteVault,
    handleCommitKeyVersion,
    handleGetVaultShare,
    handlePutVaultShares
} from '../../src/vaults.js';
import { versionedObjectKey } from '../../src/types.js';
import { createMockDB, createMockEnv, createMockR2, makeRequest, mockCtx } from '../mocks/cloudflare.js';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

function authedRequest(method: string, path: string, body?: unknown, params: Record<string, string> = {}) {
    const req = makeRequest(method, path, body) as any;
    req.user = { userId: 1, email: 'user@example.com' };
    req.params = params;
    return req;
}

const OBJECT_KEY = 'user_1_abc-123';

describe('versionedObjectKey', () => {
    it('maps v1 to the bare key so pre-migration objects stay reachable', () => {
        // Every object written before the key hierarchy lives at the bare key.
        // Suffixing v1 would have orphaned all of them.
        expect(versionedObjectKey(OBJECT_KEY, 'v1')).toBe(OBJECT_KEY);
        expect(versionedObjectKey(OBJECT_KEY, null)).toBe(OBJECT_KEY);
        expect(versionedObjectKey(OBJECT_KEY, undefined)).toBe(OBJECT_KEY);
    });

    it('suffixes later versions so a new blob sits beside the old one', () => {
        expect(versionedObjectKey(OBJECT_KEY, 'v2')).toBe(`${OBJECT_KEY}.v2`);
    });
});

describe('handleUploadVault — staged writes (#70)', () => {
    function uploadEnv(currentVersion: string) {
        const r2 = createMockR2();
        const db = createMockDB({
            'SELECT r2_object_key, current_key_version FROM vaults':
                { first: { r2_object_key: OBJECT_KEY, current_key_version: currentVersion } }
        });
        return { env: createMockEnv({ DB: db, VAULTS: r2 }), r2 };
    }

    it('writes in place when the key version is unchanged', async () => {
        const { env, r2 } = uploadEnv('v1');
        const req = authedRequest('PUT', '/api/vaults/1/data',
            { encryptedData: { iv: 'aa', ciphertext: 'bb' } }, { vaultId: '1' });

        const res = await handleUploadVault(req, env, mockCtx);
        expect(res.status).toBe(204);
        expect((r2 as any)._store.has(OBJECT_KEY)).toBe(true);
    });

    it('stages beside the live blob when writing a new key version', async () => {
        // The heart of the #70 fix. The old code overwrote in place, so an
        // interrupted re-encryption left R2 holding ciphertext under a key D1
        // had never been told about — permanently unreadable.
        const { env, r2 } = uploadEnv('v1');
        (r2 as any)._store.set(OBJECT_KEY, JSON.stringify({ iv: 'old', ciphertext: 'old' }));

        const req = authedRequest('PUT', '/api/vaults/1/data',
            { encryptedData: { iv: 'aa', ciphertext: 'bb' }, keyVersion: 'v2' }, { vaultId: '1' });

        const res = await handleUploadVault(req, env, mockCtx);
        expect(res.status).toBe(200);
        expect((await res.json() as any).staged).toBe(true);

        // Both present: the live one untouched, the new one waiting.
        expect(JSON.parse((r2 as any)._store.get(OBJECT_KEY))).toEqual({ iv: 'old', ciphertext: 'old' });
        expect(JSON.parse((r2 as any)._store.get(`${OBJECT_KEY}.v2`))).toEqual({ iv: 'aa', ciphertext: 'bb' });
    });

    it('rejects an unknown key version', async () => {
        const { env } = uploadEnv('v1');
        const req = authedRequest('PUT', '/api/vaults/1/data',
            { encryptedData: { iv: 'aa', ciphertext: 'bb' }, keyVersion: 'v99' }, { vaultId: '1' });

        expect((await handleUploadVault(req, env, mockCtx)).status).toBe(400);
    });

    it('rejects a non-numeric vault id rather than coercing it', async () => {
        const { env } = uploadEnv('v1');
        const req = authedRequest('PUT', '/api/vaults/0x10/data',
            { encryptedData: { iv: 'aa', ciphertext: 'bb' } }, { vaultId: '0x10' });

        expect((await handleUploadVault(req, env, mockCtx)).status).toBe(400);
    });
});

describe('handleDownloadVault — reads the live version', () => {
    it('serves the blob named by current_key_version', async () => {
        const r2 = createMockR2();
        (r2 as any)._store.set(OBJECT_KEY, JSON.stringify({ iv: 'old', ciphertext: 'old' }));
        (r2 as any)._store.set(`${OBJECT_KEY}.v2`, JSON.stringify({ iv: 'new', ciphertext: 'new' }));

        const db = createMockDB({
            'SELECT r2_object_key, current_key_version FROM vaults':
                { first: { r2_object_key: OBJECT_KEY, current_key_version: 'v2' } }
        });
        const env = createMockEnv({ DB: db, VAULTS: r2 });
        const req = authedRequest('GET', '/api/vaults/1/data', undefined, { vaultId: '1' });

        const body = await (await handleDownloadVault(req, env, mockCtx)).json() as any;
        expect(body.encryptedData).toEqual({ iv: 'new', ciphertext: 'new' });
        expect(body.keyVersion).toBe('v2');
    });

    it('still serves pre-migration vaults from the bare key', async () => {
        const r2 = createMockR2();
        (r2 as any)._store.set(OBJECT_KEY, JSON.stringify({ iv: 'v1', ciphertext: 'v1' }));

        const db = createMockDB({
            'SELECT r2_object_key, current_key_version FROM vaults':
                { first: { r2_object_key: OBJECT_KEY, current_key_version: 'v1' } }
        });
        const env = createMockEnv({ DB: db, VAULTS: r2 });
        const req = authedRequest('GET', '/api/vaults/1/data', undefined, { vaultId: '1' });

        const body = await (await handleDownloadVault(req, env, mockCtx)).json() as any;
        expect(body.encryptedData).toEqual({ iv: 'v1', ciphertext: 'v1' });
    });
});

describe('handleCommitKeyVersion', () => {
    function commitEnv(ownedVaultId = 1) {
        const r2 = createMockR2();
        const db = createMockDB({
            // resolveVaultAccess: direct ownership short-circuits to 'manage'
            "SELECT id FROM vaults WHERE id = ? AND owner_id": { first: { id: ownedVaultId } },
            'SELECT r2_object_key, current_key_version FROM vaults':
                { first: { r2_object_key: OBJECT_KEY, current_key_version: 'v1' } },
            'SELECT r2_object_key FROM vaults': { first: { r2_object_key: OBJECT_KEY } }
        });
        return { env: createMockEnv({ DB: db, VAULTS: r2 }), db, r2 };
    }

    it('flips every vault in one batch', async () => {
        // Partial commits are the failure this endpoint exists to prevent: half
        // the vaults pointing at new blobs and half at old ones, under two
        // different keys.
        const { env, db } = commitEnv();
        const req = authedRequest('POST', '/api/vaults/key-version/commit', {
            vaults: [{ vaultId: 1, keyVersion: 'v2' }, { vaultId: 2, keyVersion: 'v2' }]
        });

        const res = await handleCommitKeyVersion(req, env, mockCtx);
        expect(res.status).toBe(200);
        expect((db as any).batch).toHaveBeenCalledTimes(1);
        expect((db as any).batch.mock.calls[0][0]).toHaveLength(2);
    });

    it('checks permission on every vault before writing anything', async () => {
        const db = createMockDB({
            "SELECT id FROM vaults WHERE id = ? AND owner_id": { first: null },
            'SELECT permission_level FROM vault_access_controls': { first: null },
            'JOIN user_organizations uo': { first: null }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/vaults/key-version/commit', {
            vaults: [{ vaultId: 1, keyVersion: 'v2' }]
        });

        const res = await handleCommitKeyVersion(req, env, mockCtx);
        expect(res.status).toBe(403);
        expect((db as any).batch).not.toHaveBeenCalled();
    });

    it('sweeps the superseded blob once the new one is live', async () => {
        const { env, r2 } = commitEnv();
        (r2 as any)._store.set(OBJECT_KEY, 'superseded');
        (r2 as any)._store.set(`${OBJECT_KEY}.v2`, 'live');

        await handleCommitKeyVersion(authedRequest('POST', '/api/vaults/key-version/commit', {
            vaults: [{ vaultId: 1, keyVersion: 'v2' }]
        }), env, mockCtx);

        expect((r2 as any)._store.has(OBJECT_KEY)).toBe(false);
        expect((r2 as any)._store.has(`${OBJECT_KEY}.v2`)).toBe(true);
    });

    it('rejects a malformed request', async () => {
        const { env, db } = commitEnv();
        for (const body of [{}, { vaults: [] }, { vaults: [{ vaultId: 'x', keyVersion: 'v2' }] },
                            { vaults: [{ vaultId: 1, keyVersion: 'nope' }] }]) {
            const res = await handleCommitKeyVersion(
                authedRequest('POST', '/api/vaults/key-version/commit', body), env, mockCtx);
            expect(res.status).toBe(400);
        }
        expect((db as any).batch).not.toHaveBeenCalled();
    });
});

describe('handleGetVaultShare', () => {
    it('returns the caller\'s wrapped key', async () => {
        const db = createMockDB({
            'SELECT wrapped_key': { first: { wrapped_key: 'iv:ct', ephemeral_pubkey: 'EPH', key_version: 'v2' } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/vaults/1/share', undefined, { vaultId: '1' });

        const body = await (await handleGetVaultShare(req, env, mockCtx)).json() as any;
        expect(body.share.wrapped_key).toBe('iv:ct');
    });

    it('reports "authorised but keyless" distinctly from an error (#69)', async () => {
        // An org admin added after a vault was created is allowed to open it but
        // holds no key. The old code let this surface as a decryption failure
        // and told them their credentials were wrong.
        const db = createMockDB({ 'SELECT wrapped_key': { first: null } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/vaults/1/share', undefined, { vaultId: '1' });

        const res = await handleGetVaultShare(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.share).toBeNull();
        expect(body.reason).toBe('no_key_share');
    });
});

describe('handlePutVaultShares', () => {
    const SHARE = { userId: 2, wrappedKey: 'iv:ct', ephemeralPubkey: 'EPH' };

    it('writes shares for recipients who already have vault access', async () => {
        const db = createMockDB({
            "SELECT id FROM vaults WHERE id = ? AND owner_id": { first: { id: 1 } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('PUT', '/api/vaults/1/shares', { shares: [SHARE] }, { vaultId: '1' });

        const res = await handlePutVaultShares(req, env, mockCtx);
        expect(res.status).toBe(200);
        expect((db as any).batch).toHaveBeenCalledTimes(1);
    });

    it('refuses to mint a share for someone with no access to the vault', async () => {
        // Without this, holding `manage` would let you hand the vault key to an
        // arbitrary account. The server can't inspect the wrapped key — it can
        // only police who is allowed to receive one.
        const db = createMockDB({
            "SELECT id FROM vaults WHERE id = ? AND owner_id": { first: null },
            'SELECT permission_level FROM vault_access_controls': { first: null },
            'JOIN user_organizations uo': { first: null }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('PUT', '/api/vaults/1/shares', { shares: [SHARE] }, { vaultId: '1' });

        const res = await handlePutVaultShares(req, env, mockCtx);
        expect(res.status).toBe(403);
        expect((db as any).batch).not.toHaveBeenCalled();
    });

    it('clears existing shares first when rotating', async () => {
        // Revocation depends on this: a stale row would keep unwrapping the
        // previous key for someone who has been removed.
        const db = createMockDB({
            "SELECT id FROM vaults WHERE id = ? AND owner_id": { first: { id: 1 } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('PUT', '/api/vaults/1/shares',
            { shares: [SHARE], replace: true }, { vaultId: '1' });

        await handlePutVaultShares(req, env, mockCtx);
        // DELETE + one INSERT
        expect((db as any).batch.mock.calls[0][0]).toHaveLength(2);
    });

    it('rejects malformed shares', async () => {
        const db = createMockDB({ "SELECT id FROM vaults WHERE id = ? AND owner_id": { first: { id: 1 } } });
        const env = createMockEnv({ DB: db });

        for (const shares of [[], [{ userId: 0, wrappedKey: 'x', ephemeralPubkey: 'y' }],
                              [{ userId: 2, wrappedKey: '', ephemeralPubkey: 'y' }],
                              [{ userId: 2, wrappedKey: 'x' }]]) {
            const req = authedRequest('PUT', '/api/vaults/1/shares', { shares }, { vaultId: '1' });
            expect((await handlePutVaultShares(req, env, mockCtx)).status).toBe(400);
        }
    });
});

describe('r2_object_key is never disclosed to clients (#80)', () => {
    it('is absent from the create-vault response', async () => {
        const db = createMockDB({ 'INSERT INTO vaults': { run: { success: true, last_row_id: 42 } } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/vaults', {
            name: 'My Vault', ownerId: 'user_1', ownerType: 'user', initialPermissionLevel: 'manage'
        });

        const body = await (await handleCreateVault(req, env, mockCtx)).json() as any;
        expect(body.r2_object_key).toBeUndefined();
        // New vaults are born under the key hierarchy.
        expect(body.current_key_version).toBe('v2');
    });

    it('is absent from the vault list', async () => {
        const db = createMockDB({
            'FROM vaults v': { all: [{ id: 1, name: 'V', owner_id: 'user_1', owner_type: 'user', permission_level: 'manage' }] },
            'SELECT vault_id FROM vault_key_shares': { all: [{ vault_id: 1 }] }
        });
        const env = createMockEnv({ DB: db });

        const body = await (await handleGetVaults(authedRequest('GET', '/api/vaults'), env, mockCtx)).json() as any;
        for (const vault of body) {
            expect(vault.r2_object_key).toBeUndefined();
        }
    });

    it('reports whether the caller holds a key for each vault', async () => {
        // Permission and decryptability are independent facts; the UI needs both
        // to explain a vault it can see but cannot open.
        const db = createMockDB({
            'FROM vaults v': {
                all: [
                    { id: 1, name: 'Mine', owner_id: 'user_1', owner_type: 'user', permission_level: 'manage' },
                    { id: 2, name: 'Theirs', owner_id: 'org_3', owner_type: 'organization', permission_level: 'read' }
                ]
            },
            'SELECT vault_id FROM vault_key_shares': { all: [{ vault_id: 1 }] }
        });
        const env = createMockEnv({ DB: db });

        const body = await (await handleGetVaults(authedRequest('GET', '/api/vaults'), env, mockCtx)).json() as any;
        expect(body.find((v: any) => v.id === 1).has_key_share).toBe(true);
        expect(body.find((v: any) => v.id === 2).has_key_share).toBe(false);
    });
});

describe('handleDeleteVault', () => {
    it('removes every key version of the object and the key shares', async () => {
        const r2 = createMockR2();
        (r2 as any)._store.set(OBJECT_KEY, 'v1 blob');
        (r2 as any)._store.set(`${OBJECT_KEY}.v2`, 'v2 blob');

        const db = createMockDB({
            'SELECT r2_object_key, owner_id': {
                first: { r2_object_key: OBJECT_KEY, owner_id: 'user_1', owner_type: 'user', current_key_version: 'v2' }
            }
        });
        const env = createMockEnv({ DB: db, VAULTS: r2 });
        const req = authedRequest('DELETE', '/api/vaults/1', undefined, { vaultId: '1' });

        expect((await handleDeleteVault(req, env, mockCtx)).status).toBe(204);
        expect((r2 as any)._store.size).toBe(0);
        // ACL + key shares + vault row
        expect((db as any).batch.mock.calls[0][0]).toHaveLength(3);
    });
});
