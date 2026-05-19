import { describe, it, expect, vi } from 'vitest';
import { sign } from 'jsonwebtoken';
import { authenticateRequest, checkVaultPermission } from '../../src/middleware.js';
import { createMockDB, createMockEnv, makeRequest, mockCtx } from '../mocks/cloudflare.js';

const SECRET = 'test-jwt-secret-32-chars-minimum!!';

function makeToken(payload: object, secret = SECRET, opts: object = {}) {
    return sign(payload, secret, { expiresIn: '1h', ...opts });
}

// --- authenticateRequest ---

describe('authenticateRequest', () => {
    it('returns null and sets request.user for a valid token', async () => {
        const token = makeToken({ userId: 1, email: 'a@b.com' });
        const req = makeRequest('GET', '/api/vaults', undefined, {
            Authorization: `Bearer ${token}`
        }) as any;
        const env = createMockEnv({ JWT_SECRET: SECRET });

        const result = await authenticateRequest(req, env, mockCtx);
        expect(result).toBeNull();
        expect(req.user).toMatchObject({ userId: 1, email: 'a@b.com' });
    });

    it('returns 401 when no Authorization header is present', async () => {
        const req = makeRequest('GET', '/api/vaults') as any;
        const env = createMockEnv({ JWT_SECRET: SECRET });

        const result = await authenticateRequest(req, env, mockCtx);
        expect(result).toBeInstanceOf(Response);
        expect((result as Response).status).toBe(401);
    });

    it('returns 401 for a malformed Authorization header', async () => {
        const req = makeRequest('GET', '/api/vaults', undefined, {
            Authorization: 'NotBearer token'
        }) as any;
        const result = await authenticateRequest(req, createMockEnv(), mockCtx);
        expect((result as Response).status).toBe(401);
    });

    it('returns 401 for a token signed with the wrong secret', async () => {
        const token = makeToken({ userId: 1, email: 'a@b.com' }, 'wrong-secret');
        const req = makeRequest('GET', '/api/vaults', undefined, {
            Authorization: `Bearer ${token}`
        }) as any;
        const result = await authenticateRequest(req, createMockEnv(), mockCtx);
        expect((result as Response).status).toBe(401);
    });

    it('returns 401 for an expired token', async () => {
        const token = makeToken({ userId: 1, email: 'a@b.com' }, SECRET, { expiresIn: '-1s' });
        const req = makeRequest('GET', '/api/vaults', undefined, {
            Authorization: `Bearer ${token}`
        }) as any;
        const result = await authenticateRequest(req, createMockEnv({ JWT_SECRET: SECRET }), mockCtx);
        expect((result as Response).status).toBe(401);
    });
});

// --- checkVaultPermission ---

describe('checkVaultPermission', () => {
    function makeAuthedRequest(userId: number, vaultId: string) {
        const req = makeRequest('GET', `/api/vaults/${vaultId}/data`) as any;
        req.user = { userId, email: 'a@b.com', iat: 0, exp: 9999999999 };
        req.params = { vaultId };
        return req;
    }

    it('returns null when user is the direct owner of the vault', async () => {
        const db = createMockDB({
            // Direct owner check returns a row
            "owner_type = 'user'": { first: { id: 1 } }
        });
        const env = createMockEnv({ DB: db });
        const req = makeAuthedRequest(1, '1');

        const result = await checkVaultPermission(req, env, 'manage', mockCtx);
        expect(result).toBeNull();
    });

    it('returns 403 when user has no access to the vault', async () => {
        // All DB queries return null (no ownership, no access)
        const db = createMockDB({});
        const env = createMockEnv({ DB: db });
        const req = makeAuthedRequest(99, '1');

        const result = await checkVaultPermission(req, env, 'read', mockCtx);
        expect(result).toBeInstanceOf(Response);
        expect((result as Response).status).toBe(403);
    });

    it('returns 403 when user has read access but write is required', async () => {
        const db = createMockDB({
            "entity_type = 'user'": { first: { permission_level: 'read' } }
        });
        const env = createMockEnv({ DB: db });
        const req = makeAuthedRequest(2, '5');

        const result = await checkVaultPermission(req, env, 'write', mockCtx);
        expect(result).toBeInstanceOf(Response);
        expect((result as Response).status).toBe(403);
    });

    it('returns null when user has write access and write is required', async () => {
        const db = createMockDB({
            "owner_type = 'user'": { first: null },
            "entity_type = 'user'": { first: { permission_level: 'write' } }
        });
        const env = createMockEnv({ DB: db });
        const req = makeAuthedRequest(2, '5');

        const result = await checkVaultPermission(req, env, 'write', mockCtx);
        expect(result).toBeNull();
    });

    it('returns 400 for a non-numeric vault ID', async () => {
        const req = makeAuthedRequest(1, 'not-a-number');
        const result = await checkVaultPermission(req, createMockEnv(), 'read', mockCtx);
        expect((result as Response).status).toBe(400);
    });
});
