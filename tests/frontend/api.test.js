// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock fetch globally so no real HTTP calls are made
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock session — provide a valid token
vi.mock('../../public/js/session.js', () => ({
    getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test-token' }),
    clearSession: vi.fn(),
    getSessionToken: () => 'test-token'
}));

// Mock constants
vi.mock('../../public/js/constants.js', () => ({
    API_BASE_URL: '/api',
    JWT_TOKEN_KEY: 'jwtToken',
    USER_INFO_KEY: 'userInfo',
    SESSION_TIMEOUT_MINUTES: 5,
    KDF_SALT_LENGTH: 16,
    AES_IV_LENGTH: 12,
    KDF_ITERATIONS: 600000,
    KDF_MEMORY: 65536,
    KDF_PARALLELISM: 4,
    ENCRYPTION_ALGORITHM: 'AES-GCM',
    AUTH_TAG_LENGTH: 128,
    DEFAULT_MASTER_PASSWORD_CHANGE_LOADING_MESSAGE: 'Processing...'
}));

import {
    getOrgMembers,
    updateMemberRole,
    removeMember,
    deleteOrganization,
    getOrganizations,
    addMemberToOrganization,
    getVaults
} from '../../public/js/api.js';
import { clearSession } from '../../public/js/session.js';

function mockOkResponse(body, status = 200) {
    mockFetch.mockResolvedValueOnce({
        ok: true,
        status,
        json: () => Promise.resolve(body)
    });
}

beforeEach(() => {
    mockFetch.mockReset();
    clearSession.mockClear();
});

describe('getOrgMembers', () => {
    it('calls GET /api/organizations/:orgId/members', async () => {
        mockOkResponse([{ userId: 1, email: 'a@b.com', role: 'super_admin' }]);
        const result = await getOrgMembers(5);
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/organizations/5/members',
            expect.objectContaining({ method: 'GET' })
        );
        expect(result).toHaveLength(1);
        expect(result[0].role).toBe('super_admin');
    });
});

describe('updateMemberRole', () => {
    it('calls PUT /api/organizations/:orgId/members/:userId with role in body', async () => {
        mockOkResponse({ message: 'Role updated to admin.' });
        await updateMemberRole(5, 99, 'admin');
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/organizations/5/members/99',
            expect.objectContaining({
                method: 'PUT',
                body: JSON.stringify({ role: 'admin' })
            })
        );
    });
});

describe('removeMember', () => {
    it('calls DELETE /api/organizations/:orgId/members/:userId', async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 204 });
        await removeMember(5, 99);
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/organizations/5/members/99',
            expect.objectContaining({ method: 'DELETE' })
        );
    });
});

describe('deleteOrganization', () => {
    it('calls DELETE /api/organizations/:orgId', async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 204 });
        await deleteOrganization(5);
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/organizations/5',
            expect.objectContaining({ method: 'DELETE' })
        );
    });
});

describe('getOrganizations', () => {
    it('calls GET /api/organizations', async () => {
        mockOkResponse([{ id: 1, name: 'My Org', role: 'super_admin' }]);
        const result = await getOrganizations();
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/organizations',
            expect.objectContaining({ method: 'GET' })
        );
        expect(result[0].name).toBe('My Org');
    });
});

describe('addMemberToOrganization', () => {
    it('calls POST /api/organizations/:orgId/members with email and role', async () => {
        mockOkResponse({ message: 'Member added.' });
        await addMemberToOrganization(5, 'new@example.com', 'member');
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/organizations/5/members',
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({ memberEmail: 'new@example.com', role: 'member' })
            })
        );
    });

    it('throws on a non-ok response', async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 403,
            statusText: 'Forbidden',
            text: () => Promise.resolve(JSON.stringify({ message: 'Forbidden: not admin' }))
        });
        await expect(addMemberToOrganization(5, 'a@b.com', 'member')).rejects.toThrow('Forbidden: not admin');
    });
});

// A 403 (forbidden) is an authorization failure on an otherwise-valid session,
// so it must NOT log the user out — only a 401 (expired/invalid token) should.
// Regression guard for the "creating an org vault logs you out" bug.
describe('apiCall auth handling (401 vs 403)', () => {
    it('does NOT clear the session or reload on a 403', async () => {
        const reload = vi.fn();
        vi.stubGlobal('alert', vi.fn());
        vi.stubGlobal('location', { reload });
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 403,
            statusText: 'Forbidden',
            text: () => Promise.resolve(JSON.stringify({ message: 'You must be an admin of the organization to create a vault for it.' }))
        });

        await expect(getVaults()).rejects.toThrow('You must be an admin');
        expect(clearSession).not.toHaveBeenCalled();
        expect(reload).not.toHaveBeenCalled();
        vi.unstubAllGlobals();
    });

    it('clears the session and reloads on a 401', async () => {
        const reload = vi.fn();
        vi.stubGlobal('alert', vi.fn());
        vi.stubGlobal('location', { reload });
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 401,
            statusText: 'Unauthorized',
            text: () => Promise.resolve(JSON.stringify({ message: 'Unauthorized: Invalid or expired token.' }))
        });

        await expect(getVaults()).rejects.toThrow('Invalid or expired token');
        expect(clearSession).toHaveBeenCalledTimes(1);
        expect(reload).toHaveBeenCalledTimes(1);
        vi.unstubAllGlobals();
    });
});
