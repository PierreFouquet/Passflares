import { describe, it, expect, vi } from 'vitest';
import worker from '../../src/worker.js';
import { createMockEnv, mockCtx } from '../mocks/cloudflare.js';

// Build an env where ASSETS.fetch returns a fake HTML page so we can exercise
// the static-asset branch of the worker's fetch handler.
function envWithHtmlAssets(html = '<!doctype html><title>t</title>') {
    const env = createMockEnv();
    env.ASSETS = {
        fetch: vi.fn(async () =>
            new Response(html, {
                status: 200,
                headers: { 'Content-Type': 'text/html; charset=utf-8' }
            })
        )
    } as unknown as Fetcher;
    return env;
}

// Same idea for a non-HTML static asset (CSS / JS / image).
function envWithCssAssets() {
    const env = createMockEnv();
    env.ASSETS = {
        fetch: vi.fn(async () =>
            new Response('body{}', {
                status: 200,
                headers: { 'Content-Type': 'text/css' }
            })
        )
    } as unknown as Fetcher;
    return env;
}

function get(path: string) {
    return new Request(`https://passflares.test${path}`, { method: 'GET' });
}

describe('worker security headers — static / HTML responses', () => {
    it('sets HSTS with preload on HTML responses', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const hsts = res.headers.get('Strict-Transport-Security') ?? '';
        expect(hsts).toMatch(/max-age=\d+/);
        expect(hsts).toContain('includeSubDomains');
        expect(hsts).toContain('preload');
    });

    it('sets X-Content-Type-Options: nosniff on HTML responses', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    });

    it('sets Referrer-Policy on HTML responses', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    });

    it('sets X-Frame-Options: DENY on HTML responses', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    });

    it('sets Permissions-Policy on HTML responses', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const pp = res.headers.get('Permissions-Policy') ?? '';
        expect(pp).toContain('geolocation=()');
        expect(pp).toContain('microphone=()');
        expect(pp).toContain('camera=()');
    });

    it('sets a CSP on HTML responses without script-src unsafe-inline', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        expect(csp).toContain("default-src 'self'");
        // The scanner's "Unsafe security header: Content-Security-Policy"
        // finding was specifically driven by `'unsafe-inline'` on script-src.
        // Pull the script-src directive out and assert it alone.
        const scriptSrc = csp
            .split(';')
            .map((d) => d.trim())
            .find((d) => d.startsWith('script-src ')) ?? '';
        expect(scriptSrc).not.toContain("'unsafe-inline'");
    });

    it('locks down base-uri, object-src, form-action, frame-ancestors in HTML CSP', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        expect(csp).toContain("base-uri 'self'");
        expect(csp).toContain("object-src 'none'");
        expect(csp).toContain("form-action 'self'");
        expect(csp).toContain("frame-ancestors 'none'");
    });

    it('allows Cloudflare Turnstile in script-src and frame-src', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        expect(csp).toContain('https://challenges.cloudflare.com');
    });

    it('applies the same base security headers to non-HTML static assets', async () => {
        const res = await worker.fetch(get('/css/base.css'), envWithCssAssets(), mockCtx);
        expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
        expect(res.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);
        expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
        // CSP is HTML-only — CSS responses don't need one and we don't want
        // a CSP to interfere with stylesheet loading.
        expect(res.headers.get('Content-Security-Policy')).toBeNull();
    });
});

describe('worker security headers — API responses', () => {
    it('sets HSTS, nosniff, Referrer-Policy on API error responses', async () => {
        // No body → /api/login returns a 400/401 JSON. We just need any /api/*
        // path that exercises the API branch with the security wrapper.
        const req = new Request('https://passflares.test/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
        expect(res.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);
        expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    });

    it('uses a deny-by-default CSP on API responses', async () => {
        const req = new Request('https://passflares.test/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        expect(csp).toContain("default-src 'none'");
        expect(csp).toContain("frame-ancestors 'none'");
    });

    it('still sends CORS headers on API responses', async () => {
        const req = new Request('https://passflares.test/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Origin: 'https://pierrefouquet.co.uk'
            },
            body: JSON.stringify({})
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.headers.get('Access-Control-Allow-Origin'))
            .toBe('https://pierrefouquet.co.uk');
    });
});

describe('OPTIONS preflight', () => {
    it('does not 500 and returns CORS headers', async () => {
        const req = new Request('https://passflares.test/api/login', {
            method: 'OPTIONS',
            headers: { Origin: 'https://pierrefouquet.co.uk' }
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.status).toBe(204);
        expect(res.headers.get('Access-Control-Allow-Origin'))
            .toBe('https://pierrefouquet.co.uk');
    });
});
