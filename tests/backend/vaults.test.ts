import { describe, it, expect, vi } from 'vitest';
import {
    handleCreateVault,
    handleGetVaults,
    handleUploadVault,
    handleDownloadVault,
    handleDeleteVault
} from '../../src/vaults.js';
import { createMockDB, createMockEnv, createMockR2, makeRequest, mockCtx } from '../mocks/cloudflare.js';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

function authedRequest(method: string, path: string, body?: unknown, params: Record<string, string> = {}) {
    const req = makeRequest(method, path, body) as any;
    req.user = { userId: 1, email: 'user@example.com' };
    req.params = params;
    return req;
}

// --- handleCreateVault ---

describe('handleCreateVault', () => {
    it('creates a user-owned vault successfully', async () => {
        const db = createMockDB({
            'INSERT INTO vaults': { run: { success: true, last_row_id: 42 } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/vaults', {
            name: 'My Vault',
            ownerId: 'user_1',
            ownerType: 'user',
            initialPermissionLevel: 'manage'
        });

        const res = await handleCreateVault(req, env, mockCtx);
        expect(res.status).toBe(201);
        const body = await res.json() as any;
        expect(body.name).toBe('My Vault');
    });

    it('returns 403 when trying to create a vault for another user', async () => {
        const env = createMockEnv();
        const req = authedRequest('POST', '/api/vaults', {
            name: 'Vault',
            ownerId: 'user_99',
            ownerType: 'user',
            initialPermissionLevel: 'manage'
        });

        const res = await handleCreateVault(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 400 for an invalid owner type', async () => {
        const env = createMockEnv();
        const req = authedRequest('POST', '/api/vaults', {
            name: 'Vault',
            ownerId: 'user_1',
            ownerType: 'invalid',
            initialPermissionLevel: 'manage'
        });

        const res = await handleCreateVault(req, env, mockCtx);
        expect(res.status).toBe(400);
    });

    it('returns 400 when required fields are missing', async () => {
        const env = createMockEnv();
        const req = authedRequest('POST', '/api/vaults', { name: 'Vault' });

        const res = await handleCreateVault(req, env, mockCtx);
        expect(res.status).toBe(400);
    });
});

// --- handleGetVaults ---

describe('handleGetVaults', () => {
    it('returns a list of vaults for the authenticated user', async () => {
        const vaultRow = {
            id: 1, name: 'Vault 1', description: null,
            owner_id: 'user_1', owner_type: 'user',
            r2_object_key: 'key1', current_key_version: 'v1',
            permission_level: 'manage'
        };
        const db = createMockDB({
            'FROM vaults v': { all: [vaultRow] },
            "vac.entity_type = 'organization'": { all: [] }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/vaults');

        const res = await handleGetVaults(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any[];
        expect(body).toHaveLength(1);
        expect(body[0].name).toBe('Vault 1');
    });

    it('returns an empty array when user has no vaults', async () => {
        const db = createMockDB({
            'FROM vaults v': { all: [] },
            "vac.entity_type = 'organization'": { all: [] }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/vaults');

        const res = await handleGetVaults(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any[];
        expect(body).toHaveLength(0);
    });
});

// --- handleUploadVault ---

describe('handleUploadVault', () => {
    it('uploads encrypted vault data successfully', async () => {
        const r2 = createMockR2();
        const db = createMockDB({
            'SELECT r2_object_key': { first: { r2_object_key: 'user_1_abc123' } }
        });
        const env = createMockEnv({ DB: db, VAULTS: r2 });
        const req = authedRequest('PUT', '/api/vaults/1/data',
            { encryptedData: { iv: 'aabbcc', ciphertext: 'deadbeef' } },
            { vaultId: '1' }
        );

        const res = await handleUploadVault(req, env, mockCtx);
        expect(res.status).toBe(204);
        expect((r2 as any).put).toHaveBeenCalled();
    });

    it('returns 404 when vault does not exist', async () => {
        const db = createMockDB({ 'SELECT r2_object_key': { first: null } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('PUT', '/api/vaults/999/data',
            { encryptedData: { iv: 'aa', ciphertext: 'bb' } },
            { vaultId: '999' }
        );

        const res = await handleUploadVault(req, env, mockCtx);
        expect(res.status).toBe(404);
    });

    it('returns 400 when encrypted data is missing', async () => {
        const env = createMockEnv();
        const req = authedRequest('PUT', '/api/vaults/1/data', {}, { vaultId: '1' });

        const res = await handleUploadVault(req, env, mockCtx);
        expect(res.status).toBe(400);
    });
});

// --- handleDownloadVault ---

describe('handleDownloadVault', () => {
    it('downloads encrypted vault data successfully', async () => {
        const encryptedData = { iv: 'aabbcc', ciphertext: 'deadbeef' };
        const r2 = createMockR2();
        (r2 as any)._store.set('user_1_abc', JSON.stringify(encryptedData));
        (r2 as any).get = vi.fn(() =>
            Promise.resolve({ json: () => Promise.resolve(encryptedData) })
        );
        const db = createMockDB({
            'SELECT r2_object_key': { first: { r2_object_key: 'user_1_abc' } }
        });
        const env = createMockEnv({ DB: db, VAULTS: r2 });
        const req = authedRequest('GET', '/api/vaults/1/data', undefined, { vaultId: '1' });

        const res = await handleDownloadVault(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.encryptedData.iv).toBe('aabbcc');
    });

    it('returns 204 when vault exists but has no data yet', async () => {
        const r2 = createMockR2();
        (r2 as any).get = vi.fn(() => Promise.resolve(null));
        const db = createMockDB({
            'SELECT r2_object_key': { first: { r2_object_key: 'user_1_abc' } }
        });
        const env = createMockEnv({ DB: db, VAULTS: r2 });
        const req = authedRequest('GET', '/api/vaults/1/data', undefined, { vaultId: '1' });

        const res = await handleDownloadVault(req, env, mockCtx);
        expect(res.status).toBe(204);
    });

    it('returns 404 when vault does not exist', async () => {
        const db = createMockDB({ 'SELECT r2_object_key': { first: null } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/vaults/999/data', undefined, { vaultId: '999' });

        const res = await handleDownloadVault(req, env, mockCtx);
        expect(res.status).toBe(404);
    });
});

// --- handleDeleteVault ---

describe('handleDeleteVault', () => {
    it('deletes a vault and its R2 data successfully', async () => {
        const r2 = createMockR2();
        const db = createMockDB({
            'SELECT r2_object_key, owner_id': {
                first: { r2_object_key: 'user_1_abc', owner_id: 'user_1', owner_type: 'user' }
            },
            'DELETE FROM vault_access_controls': { run: { success: true } },
            'DELETE FROM vaults': { run: { success: true } }
        });
        const env = createMockEnv({ DB: db, VAULTS: r2 });
        const req = authedRequest('DELETE', '/api/vaults/1', undefined, { vaultId: '1' });

        const res = await handleDeleteVault(req, env, mockCtx);
        expect(res.status).toBe(204);
        expect((r2 as any).delete).toHaveBeenCalledWith('user_1_abc');
    });

    it('returns 404 when vault does not exist', async () => {
        const db = createMockDB({ 'SELECT r2_object_key, owner_id': { first: null } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('DELETE', '/api/vaults/999', undefined, { vaultId: '999' });

        const res = await handleDeleteVault(req, env, mockCtx);
        expect(res.status).toBe(404);
    });
});
