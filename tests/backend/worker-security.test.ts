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

// Same idea for binary/font/image asset types so we can assert header parity.
function envWithAssetContentType(contentType: string) {
    const env = createMockEnv();
    env.ASSETS = {
        fetch: vi.fn(async () =>
            new Response('binary-bytes', {
                status: 200,
                headers: { 'Content-Type': contentType }
            })
        )
    } as unknown as Fetcher;
    return env;
}

describe('worker security headers — static / HTML responses', () => {
    it('sets HSTS with preload on HTML responses', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const hsts = res.headers.get('Strict-Transport-Security') ?? '';
        expect(hsts).toMatch(/max-age=\d+/);
        expect(hsts).toContain('includeSubDomains');
        expect(hsts).toContain('preload');
    });

    it('HSTS max-age meets the scanner threshold (>= 7,776,000)', async () => {
        // Pentest-Tools flags any max-age below 7,776,000 (≈ 90 days) as too low.
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const hsts = res.headers.get('Strict-Transport-Security') ?? '';
        const m = hsts.match(/max-age=(\d+)/);
        expect(m, `Strict-Transport-Security missing max-age: "${hsts}"`).toBeTruthy();
        expect(Number(m![1])).toBeGreaterThanOrEqual(7_776_000);
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
        // 1.0.3 tightened default-src from 'self' to 'none' — deny by
        // default; every directive must explicitly opt resources back in.
        expect(csp).toContain("default-src 'none'");
        // The scanner's "Unsafe security header: Content-Security-Policy"
        // finding was specifically driven by `'unsafe-inline'` on script-src.
        // Pull the script-src directive out and assert it alone.
        const scriptSrc = csp
            .split(';')
            .map((d) => d.trim())
            .find((d) => d.startsWith('script-src ')) ?? '';
        expect(scriptSrc).not.toContain("'unsafe-inline'");
    });

    it('CSP style-src has no unsafe-inline (1.0.3 — blocks CSS keyloggers)', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        const styleSrc = csp
            .split(';')
            .map((d) => d.trim())
            .find((d) => d.startsWith('style-src ')) ?? '';
        expect(styleSrc, 'style-src directive must be present').not.toBe('');
        // Removing 'unsafe-inline' from style-src closes the CSS-keylogger
        // attack vector (e.g. `input[value^="a"] { background: url(…) }`)
        // that any HTML-injection bug would otherwise expose against the
        // master-password input.
        expect(styleSrc).not.toContain("'unsafe-inline'");
        expect(styleSrc).not.toContain("'unsafe-hashes'");
    });

    it('sets X-XSS-Protection: 0 (disables legacy auditors; CSP is the real defence)', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        // mode=block has been used to selectively disable JS in
        // otherwise-safe pages. 1.0.3 switched this to 0.
        expect(res.headers.get('X-XSS-Protection')).toBe('0');
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

    it.each([
        ['application/javascript', '/js/main.js'],
        ['font/woff2', '/fonts/inter.woff2'],
        ['image/svg+xml', '/img/logo.svg'],
        ['image/png', '/img/icon.png']
    ])('applies base security headers to %s responses', async (ct, path) => {
        const res = await worker.fetch(get(path), envWithAssetContentType(ct), mockCtx);
        expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
        expect(res.headers.get('Strict-Transport-Security')).toMatch(/max-age=/);
        expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
        expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    });

    it('HTML CSP names every expected directive', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        // Per the scanner and OWASP CSP cheat sheet — these are the directives
        // a defence-in-depth CSP for an HTML app shell should declare.
        for (const directive of [
            'default-src',
            'script-src',
            'style-src',
            'img-src',
            'font-src',
            'connect-src',
            'frame-src',
            'manifest-src',
            'base-uri',
            'object-src',
            'form-action',
            'frame-ancestors'
        ]) {
            expect(csp, `CSP missing directive "${directive}"`).toMatch(
                new RegExp(`(^|;\\s*)${directive}\\s`)
            );
        }
    });

    it('CSP script-src has no unsafe-eval, no wildcard, no data:', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        const scriptSrc = csp
            .split(';')
            .map((d) => d.trim())
            .find((d) => d.startsWith('script-src ')) ?? '';
        expect(scriptSrc).not.toContain("'unsafe-eval'");
        // A bare '*' source allows literally anything — should never appear.
        expect(scriptSrc).not.toMatch(/(^|\s)\*(\s|$)/);
        expect(scriptSrc).not.toMatch(/(^|\s)data:/);
    });

    it('no CSP directive uses a wildcard source', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        const csp = res.headers.get('Content-Security-Policy') ?? '';
        // Split on `;`, ignore the `frame-ancestors 'none'` style and look for
        // bare `*` tokens in any directive's value.
        for (const d of csp.split(';').map((d) => d.trim()).filter(Boolean)) {
            expect(d, `CSP directive "${d}" uses a wildcard *`).not.toMatch(
                /(^|\s)\*(\s|$)/
            );
        }
    });

    it('does not leak X-Powered-By or a custom Server header from the worker', async () => {
        const res = await worker.fetch(get('/'), envWithHtmlAssets(), mockCtx);
        expect(res.headers.get('X-Powered-By')).toBeNull();
        // Cloudflare appends `Server: cloudflare` after the worker returns —
        // we can only assert that *we* haven't added one ourselves.
        // (The test asset response above doesn't set Server.)
        expect(res.headers.get('Server')).toBeNull();
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
                Origin: 'https://passflares.com'
            },
            body: JSON.stringify({})
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.headers.get('Access-Control-Allow-Origin'))
            .toBe('https://passflares.com');
    });
});

describe('OPTIONS preflight', () => {
    it('does not 500 and returns CORS headers', async () => {
        const req = new Request('https://passflares.test/api/login', {
            method: 'OPTIONS',
            headers: { Origin: 'https://passflares.com' }
        });
        const res = await worker.fetch(req, createMockEnv(), mockCtx);
        expect(res.status).toBe(204);
        expect(res.headers.get('Access-Control-Allow-Origin'))
            .toBe('https://passflares.com');
    });
});
