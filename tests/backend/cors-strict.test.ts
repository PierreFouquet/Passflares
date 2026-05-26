// CORS strictness tests.
//
// The worker reflects an Origin header back only if it appears in
// `ALLOWED_ORIGINS`; anything else falls back to the production origin.
// We also assert the classic browser-rejected combination of
// `Allow-Origin: *` + `Allow-Credentials: true` never happens.

import { describe, it, expect } from 'vitest';
import worker from '../../src/worker.js';
import { createMockEnv, mockCtx } from '../mocks/cloudflare.js';

const DEFAULT_ORIGIN = 'https://pierrefouquet.co.uk';

function apiReq(origin?: string | null) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (origin !== undefined && origin !== null) headers.Origin = origin;
    return new Request('https://passflares.test/api/login', {
        method: 'POST',
        headers,
        body: JSON.stringify({})
    });
}

describe('CORS — allowed-origin gating', () => {
    it('echoes back a whitelisted origin', async () => {
        const res = await worker.fetch(apiReq(DEFAULT_ORIGIN), createMockEnv(), mockCtx);
        expect(res.headers.get('Access-Control-Allow-Origin')).toBe(DEFAULT_ORIGIN);
    });

    it('falls back to the default origin when Origin is unknown', async () => {
        const attacker = 'https://evil.example';
        const res = await worker.fetch(apiReq(attacker), createMockEnv(), mockCtx);
        const acao = res.headers.get('Access-Control-Allow-Origin');
        expect(acao).not.toBe(attacker);
        expect(acao).toBe(DEFAULT_ORIGIN);
    });

    it('falls back to the default origin when Origin is missing', async () => {
        const res = await worker.fetch(apiReq(null), createMockEnv(), mockCtx);
        expect(res.headers.get('Access-Control-Allow-Origin')).toBe(DEFAULT_ORIGIN);
    });

    it('always sets Vary: Origin so caches stay correct per requester', async () => {
        const res = await worker.fetch(apiReq(DEFAULT_ORIGIN), createMockEnv(), mockCtx);
        expect(res.headers.get('Vary')).toContain('Origin');
    });

    it('never combines Allow-Origin: * with Allow-Credentials: true', async () => {
        // Browsers reject this combination outright, but it's a common
        // misconfiguration so we explicitly assert against it.
        for (const origin of [
            null,
            DEFAULT_ORIGIN,
            'https://evil.example',
            'null',
            '*'
        ]) {
            const res = await worker.fetch(apiReq(origin), createMockEnv(), mockCtx);
            const acao = res.headers.get('Access-Control-Allow-Origin') ?? '';
            const credentials = res.headers.get('Access-Control-Allow-Credentials');
            if (acao === '*') {
                expect(credentials, 'wildcard ACAO must not be paired with credentials').not.toBe('true');
            }
            // Defence in depth — we never want a literal '*' here.
            expect(acao).not.toBe('*');
        }
    });
});

describe('CORS — OPTIONS preflight', () => {
    it('returns 204 with CORS headers for a known origin', async () => {
        const req = new Request('https://passflares.test/api/login', {
            method: 'OPTIONS',
            headers: { Origin: DEFAULT_ORIGIN }
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.status).toBe(204);
        expect(res.headers.get('Access-Control-Allow-Origin')).toBe(DEFAULT_ORIGIN);
        expect(res.headers.get('Access-Control-Allow-Methods')).toContain('POST');
        expect(res.headers.get('Access-Control-Allow-Headers')).toContain('Authorization');
    });

    it('does not echo an unknown origin in a preflight', async () => {
        const attacker = 'https://evil.example';
        const req = new Request('https://passflares.test/api/login', {
            method: 'OPTIONS',
            headers: { Origin: attacker }
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe(attacker);
    });
});
