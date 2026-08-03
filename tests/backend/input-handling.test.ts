// Regression tests for #78 — "Request handling: malformed JSON returns 500,
// unknown /api/* routes fall through to the asset handler, and no field has a
// length limit".
//
// Three gaps, one describe block each. All were verified to fail against the
// pre-fix code.

import { describe, it, expect, vi } from 'vitest';
import { sign } from 'jsonwebtoken';
import worker from '../../src/worker.js';
import { handleCreateVault } from '../../src/vaults.js';
import { handleCreateOrganization } from '../../src/organizations.js';
import { createMockDB, createMockEnv, mockCtx } from '../mocks/cloudflare.js';
import { MAX_NAME_LENGTH, MAX_DESCRIPTION_LENGTH, MAX_SECRET_LENGTH } from '../../src/utils.js';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

const SECRET = 'test-jwt-secret-32-chars-minimum!!';

function env(dbResponses = {}) {
    return createMockEnv({
        DB: createMockDB(dbResponses),
        JWT_SECRET: SECRET,
        ASSETS: { fetch: vi.fn(async () => new Response('<html>index</html>', {
            headers: { 'Content-Type': 'text/html' }
        })) } as any
    });
}

function rawRequest(method: string, path: string, body: string, headers: Record<string, string> = {}) {
    return new Request(`https://passflares.com${path}`, {
        method,
        headers: { 'Content-Type': 'application/json', ...headers },
        // GET/HEAD cannot carry one; pass '' for those.
        body: body === '' ? undefined : body
    });
}

function authedRaw(method: string, path: string, body: string) {
    const token = sign({ userId: 1, email: 'u@example.com' }, SECRET, { expiresIn: '1h' });
    return rawRequest(method, path, body, { Authorization: `Bearer ${token}` });
}

function authedHandlerReq(body: unknown, params: Record<string, string> = {}) {
    const req: any = new Request('https://passflares.com/api/x', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    req.user = { userId: 1, email: 'u@example.com' };
    req.params = params;
    return req;
}

describe('#78.1 — a malformed body is a client error, not a server error', () => {
    // The handlers destructured `await request.json()` as their first statement,
    // outside any try. The throw propagated to the catch-all in worker.ts and
    // came back as 500 {"message":"Service unavailable"}.
    const malformed = '{';

    it.each([
        ['POST', '/api/login'],
        ['POST', '/api/register']
    ])('%s %s answers 400, not 500', async (method, path) => {
        const res = await worker.fetch(rawRequest(method, path, malformed), env() as any, mockCtx);
        expect(res.status).toBe(400);
        expect((await res.json() as any).message).toMatch(/JSON/i);
    });

    it.each([
        ['POST', '/api/vaults'],
        ['POST', '/api/organizations'],
        ['POST', '/api/auth/upgrade']
    ])('%s %s answers 400, not 500', async (method, path) => {
        const res = await worker.fetch(authedRaw(method, path, malformed), env() as any, mockCtx);
        expect(res.status).toBe(400);
    });

    it('never answers "Service unavailable" for a malformed body', async () => {
        const res = await worker.fetch(rawRequest('POST', '/api/login', malformed), env() as any, mockCtx);
        expect((await res.json() as any).message).not.toMatch(/Service unavailable/);
    });

    // JSON that parses but isn't an object can't be destructured either.
    it.each(['null', '42', '"a string"', '[1,2,3]'])('rejects a non-object body: %s', async (body) => {
        const res = await worker.fetch(rawRequest('POST', '/api/login', body), env() as any, mockCtx);
        expect(res.status).toBe(400);
    });
});

describe('#78.2 — unknown /api/* routes 404 instead of serving assets', () => {
    // The catch-all handed /api/nope to env.ASSETS, which returned an HTML page
    // — served under the *API* CSP, because isApi is computed from the path
    // while the non-API CSP keys off content type.
    it('answers JSON 404 for an unknown API path', async () => {
        const e = env();
        const res = await worker.fetch(rawRequest('GET', '/api/does-not-exist', ''), e as any, mockCtx);

        expect(res.status).toBe(404);
        expect(res.headers.get('Content-Type')).toMatch(/application\/json/);
        expect((await res.json() as any).message).toMatch(/not found/i);
    });

    it('does not reach the assets binding for an unknown API path', async () => {
        const e = env();
        await worker.fetch(rawRequest('GET', '/api/does-not-exist', ''), e as any, mockCtx);
        expect((e.ASSETS as any).fetch).not.toHaveBeenCalled();
    });

    it('never returns an HTML body under the API CSP', async () => {
        const res = await worker.fetch(rawRequest('GET', '/api/nope/deeper', ''), env() as any, mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        // If this is the API CSP, the body must not be HTML.
        if (csp.includes("base-uri 'none'")) {
            expect(res.headers.get('Content-Type')).not.toMatch(/text\/html/);
        }
    });

    it('still serves real assets for non-API paths', async () => {
        const e = env();
        const res = await worker.fetch(rawRequest('GET', '/', ''), e as any, mockCtx);
        expect(res.status).toBe(200);
        expect((e.ASSETS as any).fetch).toHaveBeenCalled();
    });

    it('404s an unknown API path on every method', async () => {
        for (const method of ['GET', 'POST', 'PUT', 'DELETE']) {
            const res = await worker.fetch(
                rawRequest(method, '/api/unknown', method === 'GET' ? '' : '{}'), env() as any, mockCtx
            );
            expect(res.status, method).toBe(404);
        }
    });
});

describe('#78.3 — user-supplied fields are length-bounded', () => {
    it('rejects an over-long vault name', async () => {
        const res = await handleCreateVault(authedHandlerReq({
            name: 'x'.repeat(MAX_NAME_LENGTH + 1),
            ownerId: 'user_1',
            ownerType: 'user',
            initialPermissionLevel: 'manage'
        }), env() as any, mockCtx);
        expect(res.status).toBe(400);
    });

    it('accepts a vault name exactly at the limit', async () => {
        const res = await handleCreateVault(authedHandlerReq({
            name: 'x'.repeat(MAX_NAME_LENGTH),
            ownerId: 'user_1',
            ownerType: 'user',
            initialPermissionLevel: 'manage'
        }), env() as any, mockCtx);
        expect(res.status).toBe(201);
    });

    it('rejects an over-long vault description', async () => {
        const res = await handleCreateVault(authedHandlerReq({
            name: 'fine',
            description: 'x'.repeat(MAX_DESCRIPTION_LENGTH + 1),
            ownerId: 'user_1',
            ownerType: 'user',
            initialPermissionLevel: 'manage'
        }), env() as any, mockCtx);
        expect(res.status).toBe(400);
    });

    it('rejects an over-long organisation name', async () => {
        const res = await handleCreateOrganization(
            authedHandlerReq({ name: 'x'.repeat(MAX_NAME_LENGTH + 1) }), env() as any, mockCtx
        );
        expect(res.status).toBe(400);
    });

    it('rejects an over-long organisation description', async () => {
        const res = await handleCreateOrganization(
            authedHandlerReq({ name: 'fine', description: 'x'.repeat(MAX_DESCRIPTION_LENGTH + 1) }),
            env() as any, mockCtx
        );
        expect(res.status).toBe(400);
    });

    // The one that matters most: an unbounded credential field is fed straight
    // into scrypt at N=32768, r=12 — roughly 48 MiB of memory-hard work per
    // call, on an unauthenticated endpoint. That is an amplification primitive.
    it('rejects an oversized credential before it reaches scrypt', async () => {
        const res = await worker.fetch(
            rawRequest('POST', '/api/login', JSON.stringify({
                email: 'a@b.co',
                authSecret: 'x'.repeat(MAX_SECRET_LENGTH + 1),
                turnstileToken: 't'
            })),
            env() as any, mockCtx
        );
        expect(res.status).toBe(400);
    });

    it('caps the credential well below a megabyte', () => {
        // A regression here would be someone "relaxing" the cap to a value that
        // no longer bounds the work.
        expect(MAX_SECRET_LENGTH).toBeLessThanOrEqual(4096);
    });
});
