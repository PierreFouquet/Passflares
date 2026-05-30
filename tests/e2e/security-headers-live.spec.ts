// Opt-in live-deployment security-header probe.
//
// Skipped unless LIVE_HOST is set. Hits the deployed worker (or any URL
// you point it at) and asserts every public path carries the security
// headers a Pentest-Tools Light scan checks for.
//
// Run against the deployed worker:
//   LIVE_HOST=https://passflares.pierrefouquet.co.uk \
//     npx playwright test security-headers-live
//
// Or against a local worker (emits the same headers as production):
//   npx wrangler dev --port 8787 --local        # in one terminal
//   LIVE_HOST=http://localhost:8787 npx playwright test security-headers-live
//
// CI without LIVE_HOST set will skip this whole file — keeps offline runs
// green (the hermetic http-server can't emit the worker's headers).

import { test, expect, request as pwRequest } from '@playwright/test';

const LIVE_HOST = process.env.LIVE_HOST;

test.skip(!LIVE_HOST, 'Set LIVE_HOST to enable live security-header probes.');

// Headers every response must carry, regardless of content type.
const BASE_HEADERS = [
    'strict-transport-security',
    'x-content-type-options',
    'referrer-policy',
    'x-frame-options',
    'permissions-policy'
];

// Content-Security-Policy is applied to HTML documents and API/JSON responses,
// but deliberately NOT to static JS/CSS subresources: a CSP on a loaded
// subresource is inert, so the worker omits it there. See
// src/worker.ts `withSecurityHeaders` and tests/backend/worker-security.test.ts.
const STATIC_PATHS = ['/', '/js/main.js', '/css/base.css'];
const API_PATHS = ['/api/login', '/api/this-route-does-not-exist'];

function expectBaseHeaders(headers: Record<string, string>, path: string) {
    for (const h of BASE_HEADERS) {
        expect(
            headers[h],
            `${path} missing ${h}. headers seen: ${Object.keys(headers).join(', ')}`
        ).toBeTruthy();
    }
}

test.describe('live deployment — static asset security headers', () => {
    for (const path of STATIC_PATHS) {
        test(`${path} carries every required security header`, async () => {
            const ctx = await pwRequest.newContext();
            // Cache-bust so we don't fetch a stale edge response.
            const url = `${LIVE_HOST}${path}?cb=${Date.now()}`;
            const res = await ctx.fetch(url, { method: 'GET' });
            expect(res.status(), `${url} unexpected status`).toBeLessThan(500);

            const headers = res.headers();
            expectBaseHeaders(headers, path);

            // CSP is required on HTML documents; static JS/CSS subresources omit
            // it by design (see note above).
            if ((headers['content-type'] ?? '').includes('text/html')) {
                expect(
                    headers['content-security-policy'],
                    `${path} (HTML) missing content-security-policy`
                ).toBeTruthy();
            }

            // HSTS strength check.
            const hsts = headers['strict-transport-security'] ?? '';
            const m = hsts.match(/max-age=(\d+)/);
            expect(m, `HSTS max-age missing on ${path}`).toBeTruthy();
            expect(Number(m![1])).toBeGreaterThanOrEqual(7_776_000);
            await ctx.dispose();
        });
    }
});

test.describe('live deployment — API security headers', () => {
    for (const path of API_PATHS) {
        test(`${path} carries every required security header`, async () => {
            const ctx = await pwRequest.newContext();
            const res = await ctx.fetch(`${LIVE_HOST}${path}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                data: '{}'
            });
            const headers = res.headers();
            expectBaseHeaders(headers, path);
            // API/JSON responses carry a locked-down CSP.
            expect(
                headers['content-security-policy'],
                `${path} missing content-security-policy`
            ).toBeTruthy();
            await ctx.dispose();
        });
    }
});

test.describe('live deployment — fingerprinting we control', () => {
    test('no X-Powered-By is sent', async () => {
        const ctx = await pwRequest.newContext();
        const res = await ctx.fetch(`${LIVE_HOST}/?cb=${Date.now()}`);
        expect(res.headers()['x-powered-by']).toBeUndefined();
        await ctx.dispose();
    });
});
