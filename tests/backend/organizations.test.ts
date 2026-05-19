import { describe, it, expect, vi } from 'vitest';
import {
    handleCreateOrganization,
    handleGetOrganizations,
    handleAddMemberToOrganization
} from '../../src/organizations.js';
import { createMockDB, createMockEnv, makeRequest, mockCtx } from '../mocks/cloudflare.js';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

function authedRequest(method: string, path: string, body?: unknown, params: Record<string, string> = {}) {
    const req = makeRequest(method, path, body) as any;
    req.user = { userId: 1, email: 'admin@example.com' };
    req.params = params;
    return req;
}

// --- handleCreateOrganization ---

describe('handleCreateOrganization', () => {
    it('creates an organisation successfully', async () => {
        const db = createMockDB({
            'INSERT INTO organizations': { run: { success: true, last_row_id: 10 } },
            'INSERT INTO user_organizations': { run: { success: true } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations', {
            name: 'My Org',
            description: 'A test org'
        });

        const res = await handleCreateOrganization(req, env, mockCtx);
        expect(res.status).toBe(201);
        const body = await res.json() as any;
        expect(body.name).toBe('My Org');
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
        const orgRow = { id: 1, name: 'My Org', description: null, role: 'admin' };
        const db = createMockDB({
            'FROM organizations o': { all: [orgRow] }
        });
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

// --- handleAddMemberToOrganization ---

describe('handleAddMemberToOrganization', () => {
    const adminRole = { role: 'admin' };
    const memberUser = { id: 99 };

    it('adds a member to the organisation successfully', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: adminRole },
            'SELECT id FROM users': { first: memberUser },
            'SELECT * FROM user_organizations': { first: null }, // not already a member
            'INSERT INTO user_organizations': { run: { success: true } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'newmember@example.com', role: 'member' },
            { orgId: '1' }
        );

        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(200);
    });

    it('returns 403 when the requesting user is not an org admin', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: { role: 'member' } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'new@example.com', role: 'member' },
            { orgId: '1' }
        );

        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(403);
    });

    it('returns 404 when the member email does not exist', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: adminRole },
            'SELECT id FROM users': { first: null }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'nobody@example.com', role: 'member' },
            { orgId: '1' }
        );

        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(404);
    });

    it('returns 409 when the user is already a member', async () => {
        const db = createMockDB({
            'SELECT role FROM user_organizations': { first: adminRole },
            'SELECT id FROM users': { first: memberUser },
            'SELECT * FROM user_organizations': { first: { user_id: 99, organization_id: 1 } }
        });
        const env = createMockEnv({ DB: db });
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'existing@example.com', role: 'member' },
            { orgId: '1' }
        );

        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(409);
    });

    it('returns 400 when the role is invalid', async () => {
        const env = createMockEnv();
        const req = authedRequest('POST', '/api/organizations/1/members',
            { memberEmail: 'a@b.com', role: 'superuser' },
            { orgId: '1' }
        );

        const res = await handleAddMemberToOrganization(req, env, mockCtx);
        expect(res.status).toBe(400);
    });
});
