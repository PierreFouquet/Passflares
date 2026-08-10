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

    // The 2FA step-up token is minted after the password check but before the
    // second factor. Accepting it on a protected route would let anyone who
    // knows only the password through — a full 2FA bypass. Nothing asserted
    // this until #83: the token was only ever handed to the TOTP handlers.
    it('returns 401 for the short-lived 2FA step-up token', async () => {
        const temp = makeToken({ sub: 1, email: 'a@b.com', scope: '2fa' }, SECRET, { expiresIn: '5m' });
        const req = makeRequest('GET', '/api/vaults', undefined, {
            Authorization: `Bearer ${temp}`
        }) as any;

        const result = await authenticateRequest(req, createMockEnv({ JWT_SECRET: SECRET }), mockCtx);
        expect((result as Response).status).toBe(401);
        expect(req.user).toBeUndefined();
    });

    it('returns 401 for a validly signed token that carries no userId', async () => {
        const token = makeToken({ sub: 1, email: 'a@b.com' }, SECRET);
        const req = makeRequest('GET', '/api/vaults', undefined, {
            Authorization: `Bearer ${token}`
        }) as any;

        const result = await authenticateRequest(req, createMockEnv({ JWT_SECRET: SECRET }), mockCtx);
        expect((result as Response).status).toBe(401);
        expect(req.user).toBeUndefined();
    });

    it('returns 401 when userId is present but not a number', async () => {
        const token = makeToken({ userId: '1', email: 'a@b.com' }, SECRET);
        const req = makeRequest('GET', '/api/vaults', undefined, {
            Authorization: `Bearer ${token}`
        }) as any;

        const result = await authenticateRequest(req, createMockEnv({ JWT_SECRET: SECRET }), mockCtx);
        expect((result as Response).status).toBe(401);
    });
});

// --- checkVaultPermission ---
//
// BRANCH COVERAGE ONLY. These drive the substring-matching mock, which returns
// the same canned row whatever is bound, so nothing below can show that a query
// is scoped to the right user or the right vault. "Returns null when user is the
// direct owner" passes just as happily if the SQL drops `AND owner_id = ?`.
//
// Not a guess — measured. Pointing the falsifiability gate at this file alone:
//
//   node scripts/mutation-check.mjs --only mw-owner-any-vault \
//        --targets tests/backend/middleware.test.ts
//
// mw-owner-any-vault, mw-acl-any-user and mw-org-any-member all SURVIVE here.
// They are killed by integration/vault-permission-real-db.test.ts, which is
// where the authorization boundary is actually asserted, against real SQL where
// bound parameters decide the answer (#89 §6, #83 §1).
//
// What these keep earning: the argument-validation and control-flow arms —
// bad vault id, absent user context, the 401/400 paths — which need no database
// and are cheaper to state here.

describe('checkVaultPermission (branch coverage; scoping lives in the integration suite)', () => {
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

    // Guards the `!user || !user.userId` arm. Reaching the DB with no identity
    // would look up `user_undefined` and deny by accident rather than by rule.
    it('returns 401 when the request carries no user context', async () => {
        const req = makeRequest('GET', '/api/vaults/1/data') as any;
        req.params = { vaultId: '1' };

        const result = await checkVaultPermission(req, createMockEnv(), 'read', mockCtx);
        expect((result as Response).status).toBe(401);
    });

    it('returns 401 when the user context has no userId', async () => {
        const req = makeRequest('GET', '/api/vaults/1/data') as any;
        req.params = { vaultId: '1' };
        req.user = { email: 'a@b.com', iat: 0, exp: 9999999999 };

        const result = await checkVaultPermission(req, createMockEnv(), 'read', mockCtx);
        expect((result as Response).status).toBe(401);
    });
});
