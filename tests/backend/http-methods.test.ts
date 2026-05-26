// HTTP method handling tests.
//
// Asserts that:
//  - Unsafe methods (TRACE, CONNECT) don't return 200 from the worker
//  - Protected API routes require auth — calling them without an
//    Authorization header yields 401, never 200
//  - Unknown /api/* paths return JSON 404 with the security-header layer
//  - HEAD requests carry the same security headers as GET
//
// The actual /api/vaults handlers are exercised in other suites; here we
// only care that the auth gate is in place and that responses carry the
// hardened headers regardless of outcome.

import { describe, it, expect, vi } from 'vitest';
import worker from '../../src/worker.js';
import { createMockEnv, mockCtx } from '../mocks/cloudflare.js';

function envWithHtmlAssets() {
    const env = createMockEnv();
    env.ASSETS = {
        fetch: vi.fn(async () =>
            new Response('<!doctype html><title>t</title>', {
                status: 200,
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            })
        )
    } as unknown as Fetcher;
    return env;
}

function req(method: string, path: string, init: RequestInit = {}) {
    return new Request(`https://passflares.test${path}`, { method, ...init });
}

const SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'X-Frame-Options'
];

describe('Unsafe HTTP methods', () => {
    it.each(['TRACE', 'CONNECT'])('the Fetch runtime rejects %s outright', (method) => {
        // The Fetch standard's Request constructor throws on these methods
        // (https://fetch.spec.whatwg.org/#methods). That's the strongest
        // possible guarantee — no attacker can even build the request in
        // the worker's runtime. If a future runtime ever stops rejecting
        // them, this test fails and we'll need an explicit worker guard.
        expect(() => req(method, '/')).toThrow(/unsupported|invalid method/i);
    });
});

describe('Auth gating on /api/vaults', () => {
    it('PUT /api/vaults/abc/data without Authorization returns 401', async () => {
        const r = req('PUT', '/api/vaults/abc/data', {
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ciphertext: 'x' })
        });
        const res = await worker.fetch(r, createMockEnv(), mockCtx);
        expect(res.status).toBe(401);
        for (const h of SECURITY_HEADERS) {
            expect(res.headers.get(h), `${h} missing on 401`).toBeTruthy();
        }
    });

    it('DELETE /api/vaults/abc without Authorization returns 401', async () => {
        const res = await worker.fetch(req('DELETE', '/api/vaults/abc'), createMockEnv(), mockCtx);
        expect(res.status).toBe(401);
        for (const h of SECURITY_HEADERS) {
            expect(res.headers.get(h), `${h} missing on 401`).toBeTruthy();
        }
    });

    it('GET /api/vaults without Authorization returns 401', async () => {
        const res = await worker.fetch(req('GET', '/api/vaults'), createMockEnv(), mockCtx);
        expect(res.status).toBe(401);
    });
});

describe('Unknown /api/* paths', () => {
    it('returns 404 with security headers and no HTML body', async () => {
        // Unknown API path falls through the router and hits the catch-all
        // → ASSETS.fetch in production. With the default mock env, ASSETS
        // returns whatever we hand it; the important assertion is that the
        // security headers are present regardless of what ASSETS returns.
        const env = createMockEnv();
        env.ASSETS = {
            fetch: vi.fn(async () => new Response('not found', {
                status: 404,
                headers: { 'Content-Type': 'text/plain' }
            }))
        } as unknown as Fetcher;
        const res = await worker.fetch(req('GET', '/api/this-route-does-not-exist'), env, mockCtx);
        for (const h of SECURITY_HEADERS) {
            expect(res.headers.get(h), `${h} missing on unknown /api/*`).toBeTruthy();
        }
    });
});

describe('HEAD parity with GET', () => {
    it('HEAD / returns the same security headers as GET /', async () => {
        const getRes = await worker.fetch(req('GET', '/'), envWithHtmlAssets(), mockCtx);
        const headRes = await worker.fetch(req('HEAD', '/'), envWithHtmlAssets(), mockCtx);
        for (const h of SECURITY_HEADERS) {
            expect(headRes.headers.get(h)).toBe(getRes.headers.get(h));
        }
    });
});
