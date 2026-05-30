// Canonical-host redirect tests.
//
// `www.passflares.com` is routed to the Worker but is not the canonical
// origin: every request to it must 301 to the bare apex `passflares.com`,
// preserving path + query. Requests already on the apex pass through.

import { describe, it, expect } from 'vitest';
import worker from '../../src/worker.js';
import { createMockEnv, mockCtx } from '../mocks/cloudflare.js';

describe('Canonical host — www → apex redirect', () => {
    it('301s a www request to the apex, preserving path and query', async () => {
        const req = new Request('https://www.passflares.com/dashboard?tab=vaults');
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.status).toBe(301);
        expect(res.headers.get('Location'))
            .toBe('https://passflares.com/dashboard?tab=vaults');
    });

    it('redirects the www root to the apex root', async () => {
        const req = new Request('https://www.passflares.com/');
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.status).toBe(301);
        expect(res.headers.get('Location')).toBe('https://passflares.com/');
    });

    it('carries HSTS on the redirect response', async () => {
        const req = new Request('https://www.passflares.com/');
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');
    });

    it('does not redirect a request already on the apex', async () => {
        const req = new Request('https://passflares.com/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.status).not.toBe(301);
    });
});
