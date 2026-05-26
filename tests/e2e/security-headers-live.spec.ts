// Opt-in live-deployment security-header probe.
//
// Skipped unless LIVE_HOST is set. Hits the deployed worker (or any URL
// you point it at) and asserts every public path carries the security
// headers a Pentest-Tools Light scan checks for.
//
// Run:
//   LIVE_HOST=https://passflares.pierrefouquet.co.uk \
//     npx playwright test security-headers-live
//
// CI without LIVE_HOST set will skip this whole file — keeps offline runs
// green.

import { test, expect, request as pwRequest } from '@playwright/test';

const LIVE_HOST = process.env.LIVE_HOST;

test.skip(!LIVE_HOST, 'Set LIVE_HOST to enable live security-header probes.');

const REQUIRED_HEADERS = [
    'content-security-policy',
    'strict-transport-security',
    'x-content-type-options',
    'referrer-policy',
    'x-frame-options',
    'permissions-policy'
];

// Paths we expect to carry the full security-header set.
const STATIC_PATHS = ['/', '/js/main.js', '/css/base.css'];

// API paths — same headers expected (CSP differs but is still present).
const API_PATHS = ['/api/login', '/api/this-route-does-not-exist'];

test.describe('live deployment — static asset security headers', () => {
    for (const path of STATIC_PATHS) {
        test(`${path} carries every required security header`, async () => {
            const ctx = await pwRequest.newContext();
            // Cache-bust so we don't fetch a stale edge response.
            const url = `${LIVE_HOST}${path}?cb=${Date.now()}`;
            const res = await ctx.fetch(url, { method: 'GET' });
            expect(res.status(), `${url} unexpected status`).toBeLessThan(500);

            const headers = res.headers();
            for (const h of REQUIRED_HEADERS) {
                expect(
                    headers[h],
                    `${path} missing ${h}. headers seen: ${Object.keys(headers).join(', ')}`
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
            for (const h of REQUIRED_HEADERS) {
                expect(
                    headers[h],
                    `${path} missing ${h}. headers seen: ${Object.keys(headers).join(', ')}`
                ).toBeTruthy();
            }
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
