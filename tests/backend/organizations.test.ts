import { describe, it, expect, vi } from 'vitest';
import {
    handleCreateOrganization,
    handleGetOrganizations,
    handleAddMemberToOrganization,
    handleGetOrgMembers,
    handleUpdateMemberRole,
    handleRemoveMember,
    handleDeleteOrganization
} from '../../src/organizations.js';
import { createMockDB, createMockEnv, createMockR2, makeRequest, mockCtx } from '../mocks/cloudflare.js';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

function authedRequest(method: string, path: string, body?: unknown, params: Record<string, string> = {}) {
    const req = makeRequest(method, path, body) as any;
    req.user = { userId: 1, email: 'admin@example.com' };
    req.params = params;
    return req;
}

// --- handleCreateOrganization ---

describe('handleCreateOrganization', () => {
    it('creates an organisation and assigns super_admin role to creator', async () => {
        const db = createMockDB({
            'INSERT INTO organizations': { run: { success: true, last_row_id: 10 } },
            'INSERT INTO user_organizations': { run: { success: true } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations', { name: 'My Org', description: 'A test org' });

        const res = await handleCreateOrganization(req, env, mockCtx);
        expect(res.status).toBe(201);
        const body = await res.json() as any;
        expect(body.name).toBe('My Org');
        expect(body.role).toBe('super_admin');
    });

    it('returns 400 when name is missing', async () => {
        const env = createMockEnv();
        const req = authedRequest('POST', '/api/organizations', { description: 'No name' });
        const res = await handleCreateOrganization(req, env, mockCtx);
        expect(res.status).toBe(400);
    });

    it('returns 401 when user is not authenticated', async () => {
        const env = createMockEnv();
        const req = makeRequest('POST', '/api/organizations', { name: 'Org' }) as any;
        req.user = undefined;
        req.params = {};
        const res = await handleCreateOrganization(req, env, mockCtx);
        expect(res.status).toBe(401);
    });
});

// --- handleGetOrganizations ---

describe('handleGetOrganizations', () => {
    it('returns organisations the user belongs to', async () => {
        const orgRow = { id: 1, name: 'My Org', description: null, role: 'super_admin' };
        const db = createMockDB({ 'FROM organizations o': { all: [orgRow] } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/organizations');

        const res = await handleGetOrganizations(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any[];
        expect(body).toHaveLength(1);
        expect(body[0].name).toBe('My Org');
    });

    it('returns an empty array when user has no organisations', async () => {
        const db = createMockDB({ 'FROM organizations o': { all: [] } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/organizations');
        const res = await handleGetOrganizations(req, env, mockCtx);
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual([]);
    });
});

// --- handleGetOrgMembers ---

describe('handleGetOrgMembers', () => {
    it('returns member list for a member of the org', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: { role: 'super_admin' } },
            'JOIN users u ON': { all: [{ userId: 1, email: 'owner@example.com', role: 'super_admin' }] }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/organizations/1/members', undefined, { orgId: '1' });

        const res = await handleGetOrgMembers(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any[];
        expect(body).toHaveLength(1);
    });

    it('returns 403 when caller is not a member', async () => {
        const db = createMockDB({ 'SELECT role FROM user_organizations': { first: null } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('GET', '/api/organizations/1/members', undefined, { orgId: '1' });
        const res = await handleGetOrgMembers(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 400 on invalid orgId', async () => {
        const env = createMockEnv();
        const req = authedRequest('GET', '/api/organizations/bad/members', undefined, { orgId: 'bad' });
        const res = await handleGetOrgMembers(req, env, mockCtx);
        expect(res.status).toBe(400);
    });
});

// --- handleUpdateMemberRole ---

describe('handleUpdateMemberRole', () => {
    it('returns 200 when super_admin changes a member role', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?': { first: { role: 'super_admin' } }
        });
        // Two calls to the same pattern — first for caller, second for target
        let callCount = 0;
        (db as any).prepare = vi.fn((sql: string) => ({
            bind: vi.fn(() => ({
                first: vi.fn(() => {
                    if (sql.includes('SELECT role FROM user_organizations')) {
                        callCount++;
                        return Promise.resolve({ role: callCount === 1 ? 'super_admin' : 'member' });
                    }
                    return Promise.resolve(null);
                }),
                run: vi.fn(() => Promise.resolve({ success: true, meta: { last_row_id: 1, changes: 1 }, results: [] })),
                all: vi.fn(() => Promise.resolve({ results: [], success: true }))
            }))
        }));
        (db as any).exec = vi.fn(() => Promise.resolve());
        (db as any).batch = vi.fn(() => Promise.resolve([]));

        const env = createMockEnv({ DB: db });
        const req = authedRequest('PUT', '/api/organizations/1/members/2', { role: 'admin' }, { orgId: '1', memberUserId: '2' });
        const res = await handleUpdateMemberRole(req, env, mockCtx);
        expect(res.status).toBe(200);
    });

    it('returns 403 when caller is not super_admin', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: { role: 'admin' } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('PUT', '/api/organizations/1/members/2', { role: 'member' }, { orgId: '1', memberUserId: '2' });
        const res = await handleUpdateMemberRole(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 403 when caller tries to change own role', async () => {
        const env = createMockEnv();
        const req = authedRequest('PUT', '/api/organizations/1/members/1', { role: 'member' }, { orgId: '1', memberUserId: '1' });
        const res = await handleUpdateMemberRole(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 400 on invalid role value', async () => {
        const env = createMockEnv();
        const req = authedRequest('PUT', '/api/organizations/1/members/2', { role: 'god' }, { orgId: '1', memberUserId: '2' });
        const res = await handleUpdateMemberRole(req, env, mockCtx);
        expect(res.status).toBe(400);
    });
});

// --- handleRemoveMember ---

describe('handleRemoveMember', () => {
    it('returns 204 when admin removes a regular member', async () => {
        let callCount = 0;
        const db = createMockDB({});
        (db as any).prepare = vi.fn((sql: string) => ({
            bind: vi.fn(() => ({
                first: vi.fn(() => {
                    callCount++;
                    if (callCount === 1) return Promise.resolve({ role: 'admin' });   // caller
                    if (callCount === 2) return Promise.resolve({ role: 'member' });  // target
                    return Promise.resolve(null);
                }),
                run: vi.fn(() => Promise.resolve({ success: true, meta: { last_row_id: 1 }, results: [] })),
                all: vi.fn(() => Promise.resolve({ results: [], success: true }))
            }))
        }));
        (db as any).exec = vi.fn(() => Promise.resolve());
        (db as any).batch = vi.fn(() => Promise.resolve([]));

        const env = createMockEnv({ DB: db });
        const req = authedRequest('DELETE', '/api/organizations/1/members/2', undefined, { orgId: '1', memberUserId: '2' });
        const res = await handleRemoveMember(req, env, mockCtx);
        expect(res.status).toBe(204);
    });

    it('returns 403 when trying to remove self', async () => {
        const env = createMockEnv();
        const req = authedRequest('DELETE', '/api/organizations/1/members/1', undefined, { orgId: '1', memberUserId: '1' });
        const res = await handleRemoveMember(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 403 when admin tries to remove a super_admin', async () => {
        let callCount = 0;
        const db = createMockDB({});
        (db as any).prepare = vi.fn(() => ({
            bind: vi.fn(() => ({
                first: vi.fn(() => {
                    callCount++;
                    if (callCount === 1) return Promise.resolve({ role: 'admin' });        // caller
                    if (callCount === 2) return Promise.resolve({ role: 'super_admin' });  // target
                    return Promise.resolve(null);
                }),
                run: vi.fn(() => Promise.resolve({ success: true, meta: { last_row_id: 1 }, results: [] })),
                all: vi.fn(() => Promise.resolve({ results: [], success: true }))
            }))
        }));
        (db as any).exec = vi.fn(() => Promise.resolve());
        (db as any).batch = vi.fn(() => Promise.resolve([]));

        const env = createMockEnv({ DB: db });
        const req = authedRequest('DELETE', '/api/organizations/1/members/2', undefined, { orgId: '1', memberUserId: '2' });
        const res = await handleRemoveMember(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 403 when a regular member tries to remove someone', async () => {
        const db = createMockDB({ 'SELECT role FROM user_organizations': { first: { role: 'member' } } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('DELETE', '/api/organizations/1/members/3', undefined, { orgId: '1', memberUserId: '3' });
        const res = await handleRemoveMember(req, env, mockCtx);
        expect(res.status).toBe(403);
    });
});

// --- handleDeleteOrganization ---

describe('handleDeleteOrganization', () => {
    it('returns 204 and deletes R2 objects when called by super_admin', async () => {
        const r2 = createMockR2();
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: { role: 'super_admin' } },
            'SELECT r2_object_key FROM vaults': { all: [{ r2_object_key: 'org_1_abc' }] }
        });
        const env = createMockEnv({ DB: db, VAULTS: r2 });
        const req = authedRequest('DELETE', '/api/organizations/1', undefined, { orgId: '1' });

        const res = await handleDeleteOrganization(req, env, mockCtx);
        expect(res.status).toBe(204);
        expect((r2 as any).delete).toHaveBeenCalledWith('org_1_abc');
    });

    it('returns 403 when caller is admin but not super_admin', async () => {
        const db = createMockDB({ 'SELECT role FROM user_organizations': { first: { role: 'admin' } } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('DELETE', '/api/organizations/1', undefined, { orgId: '1' });
        const res = await handleDeleteOrganization(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 403 when caller is not a member', async () => {
        const db = createMockDB({ 'SELECT role FROM user_organizations': { first: null } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('DELETE', '/api/organizations/1', undefined, { orgId: '1' });
        const res = await handleDeleteOrganization(req, env, mockCtx);
        expect(res.status).toBe(403);
    });
});

// --- handleAddMemberToOrganization ---

describe('handleAddMemberToOrganization', () => {
    const adminRole = { role: 'admin' };
    const superAdminRole = { role: 'super_admin' };
    const memberUser = { id: 99 };

    it('adds a member when called by admin', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: adminRole },
            'SELECT id FROM users': { first: memberUser },
            'SELECT * FROM user_organizations': { first: null },
            'INSERT INTO user_organizations': { run: { success: true } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'new@example.com', role: 'member' }, { orgId: '1' });
        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(200);
    });

    it('adds a member when called by super_admin', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: superAdminRole },
            'SELECT id FROM users': { first: memberUser },
            'SELECT * FROM user_organizations': { first: null },
            'INSERT INTO user_organizations': { run: { success: true } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'new@example.com', role: 'member' }, { orgId: '1' });
        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(200);
    });

    it('returns 403 when caller is a regular member', async () => {
        const db = createMockDB({ 'SELECT role FROM user_organizations': { first: { role: 'member' } } });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'a@b.com', role: 'member' }, { orgId: '1' });
        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 404 when member email does not exist', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: adminRole },
            'SELECT id FROM users': { first: null }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'nobody@example.com', role: 'member' }, { orgId: '1' });
        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(404);
    });

    it('returns 409 when user is already a member', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: adminRole },
            'SELECT id FROM users': { first: memberUser },
            'SELECT * FROM user_organizations': { first: { user_id: 99, organization_id: 1 } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'existing@example.com', role: 'member' }, { orgId: '1' });
        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(409);
    });

    it('returns 400 when role is invalid', async () => {
        const env = createMockEnv();
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'a@b.com', role: 'super_admin' }, { orgId: '1' });
        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(400);
    });
});
