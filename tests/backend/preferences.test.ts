import { describe, it, expect, vi } from 'vitest';
import { handleGetPreferences, handleUpdatePreferences } from '../../src/preferences.js';
import { createMockDB, createMockEnv, makeRequest, mockCtx } from '../mocks/cloudflare.js';

vi.mock('../../src/auditLog.js', () => ({
    logAudit: vi.fn()
}));

const SAVED_ROW = {
    user_id: 1,
    theme: 'dark',
    density: 'compact',
    shape: 'pill',
    accent: 'purple',
    updated_at: '2026-05-20T00:00:00Z'
};

function envWithRows(rows: Record<string, unknown>) {
    return createMockEnv({ DB: createMockDB(rows) });
}

function authReq(method: 'GET' | 'PUT', body?: unknown, userId = 1) {
    const req = makeRequest(method, '/api/users/me/preferences', body) as any;
    req.user = { userId, email: `u${userId}@example.com` };
    return req;
}

// --- handleGetPreferences ---

describe('handleGetPreferences', () => {
    it('returns 401 when unauthenticated', async () => {
        const env = envWithRows({});
        const req = makeRequest('GET', '/api/users/me/preferences') as any;
        // no req.user
        const res = await handleGetPreferences(req, env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('returns defaults when no preferences row exists', async () => {
        const env = envWithRows({ 'FROM user_preferences': { first: null } });
        const req = authReq('GET');
        const res = await handleGetPreferences(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body).toMatchObject({
            user_id: 1,
            theme: 'system',
            density: 'comfortable',
            shape: 'rounded',
            accent: 'emerald'
        });
    });

    it('returns stored row when one exists', async () => {
        const env = envWithRows({ 'FROM user_preferences': { first: SAVED_ROW } });
        const req = authReq('GET');
        const res = await handleGetPreferences(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body).toEqual(SAVED_ROW);
    });

    it('returns 500 when DB throws', async () => {
        const env = createMockEnv({
            DB: { prepare: vi.fn(() => { throw new Error('boom'); }) } as any
        });
        const req = authReq('GET');
        const res = await handleGetPreferences(req, env, mockCtx);
        expect(res.status).toBe(500);
    });
});

// --- handleUpdatePreferences ---

describe('handleUpdatePreferences', () => {
    it('returns 401 when unauthenticated', async () => {
        const env = envWithRows({});
        const req = makeRequest('PUT', '/api/users/me/preferences', { theme: 'dark' }) as any;
        const res = await handleUpdatePreferences(req, env, mockCtx);
        expect(res.status).toBe(401);
    });

    it('upserts new preferences when no row exists', async () => {
        const env = envWithRows({
            // First SELECT (existing prefs lookup) returns null
            // The INSERT/UPSERT run() is OK by default
            // The second SELECT returns the saved row
            'FROM user_preferences': { first: SAVED_ROW }
        });
        const req = authReq('PUT', { theme: 'dark', density: 'compact', shape: 'pill', accent: 'purple' });
        const res = await handleUpdatePreferences(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.theme).toBe('dark');
        expect(body.density).toBe('compact');
        expect(body.shape).toBe('pill');
        expect(body.accent).toBe('purple');
    });

    it('accepts a partial update and preserves untouched fields', async () => {
        const existing = { theme: 'dark', density: 'compact', shape: 'pill', accent: 'purple' };
        let selectCallCount = 0;
        const db = {
            prepare: vi.fn((sql: string) => ({
                bind: vi.fn(() => ({
                    first: vi.fn(() => {
                        if (!sql.includes('FROM user_preferences')) return Promise.resolve(null);
                        selectCallCount += 1;
                        // First select (existing lookup): return existing row
                        // Second select (post-write read-back): return the merged row
                        if (selectCallCount === 1) return Promise.resolve(existing);
                        return Promise.resolve({ ...existing, theme: 'light', user_id: 1, updated_at: 'now' });
                    }),
                    run: vi.fn(() => Promise.resolve({ success: true, meta: { last_row_id: 1 }, results: [] })),
                    all: vi.fn(() => Promise.resolve({ results: [], success: true }))
                }))
            }))
        } as unknown as D1Database;
        const env = createMockEnv({ DB: db });
        const req = authReq('PUT', { theme: 'light' });

        const res = await handleUpdatePreferences(req, env, mockCtx);
        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.theme).toBe('light');
        // untouched fields preserved
        expect(body.density).toBe('compact');
        expect(body.shape).toBe('pill');
        expect(body.accent).toBe('purple');
    });

    it.each([
        ['theme',   'neon'],
        ['density', 'huge'],
        ['shape',   'square'],
        ['accent',  'crimson']
    ])('rejects invalid value for %s = %s', async (field, value) => {
        const env = envWithRows({ 'FROM user_preferences': { first: null } });
        const req = authReq('PUT', { [field]: value });
        const res = await handleUpdatePreferences(req, env, mockCtx);
        expect(res.status).toBe(400);
        const body = await res.json() as any;
        expect(body.allowed).toBeDefined();
    });

    it('returns 400 on invalid JSON body', async () => {
        const env = envWithRows({});
        const req = new Request('https://passflares.test/api/users/me/preferences', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: '{not-json'
        }) as any;
        req.user = { userId: 1 };
        const res = await handleUpdatePreferences(req, env, mockCtx);
        expect(res.status).toBe(400);
    });
});
