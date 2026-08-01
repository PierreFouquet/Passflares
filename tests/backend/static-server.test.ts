// Regression tests for scripts/static-server.mjs.
//
// These exist because CodeQL, not the local suite, caught the original version's
// problems: three path-injection warnings and — behind them — a real crash. A
// request for `/%` reached an unguarded `decodeURIComponent`, which throws
// URIError, which killed the whole process. `npm test` was green throughout.
//
// The server only ever serves fixtures to Playwright, so the blast radius was
// small. The lesson is not: it was reachable, unhandled, and invisible to the
// tests that ran before pushing. Anything accepting untrusted input needs
// behavioural coverage of the malformed cases, not just the happy path.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const serverScript = resolve(repoRoot, 'scripts/static-server.mjs');

// High port to avoid colliding with the Playwright server on 4173.
const PORT = 47318;
const BASE = `http://127.0.0.1:${PORT}`;

let proc: ChildProcess;

beforeAll(async () => {
    proc = spawn('node', [serverScript, 'public', String(PORT)], {
        cwd: repoRoot,
        stdio: ['ignore', 'pipe', 'pipe']
    });

    // Wait for the listen banner rather than sleeping a fixed interval.
    await new Promise<void>((resolveReady, rejectReady) => {
        const timer = setTimeout(() => rejectReady(new Error('static-server did not start')), 10_000);
        proc.stdout!.on('data', (chunk: Buffer) => {
            if (chunk.toString().includes('static-server:')) {
                clearTimeout(timer);
                resolveReady();
            }
        });
        proc.on('exit', (code) => {
            clearTimeout(timer);
            rejectReady(new Error(`static-server exited early with code ${code}`));
        });
    });
});

afterAll(() => {
    proc?.kill();
});

/** True while the process is still running and answering. */
async function isAlive(): Promise<boolean> {
    if (proc.exitCode !== null) return false;
    try {
        return (await fetch(`${BASE}/`)).ok;
    } catch {
        return false;
    }
}

describe('static-server — serves the fixture tree', () => {
    it('serves the app shell at / and at /index.html', async () => {
        for (const path of ['/', '/index.html']) {
            const res = await fetch(`${BASE}${path}`);
            expect(res.status, path).toBe(200);
            expect(res.headers.get('content-type')).toContain('text/html');
        }
    });

    it('serves nested assets with the right content type', async () => {
        const js = await fetch(`${BASE}/js/main.js`);
        expect(js.status).toBe(200);
        expect(js.headers.get('content-type')).toContain('text/javascript');

        // The vendored Argon2id modules must be reachable, or every E2E sign-in
        // fails at the key-derivation step.
        const argon = await fetch(`${BASE}/vendor/noble-hashes/argon2.js`);
        expect(argon.status).toBe(200);
    });

    it('serves index.html for a nested directory', async () => {
        expect((await fetch(`${BASE}/docs/`)).status).toBe(200);
    });

    it('disables caching so E2E never sees a stale asset', async () => {
        expect((await fetch(`${BASE}/`)).headers.get('cache-control')).toBe('no-store');
    });

    it('404s an unknown path', async () => {
        expect((await fetch(`${BASE}/does-not-exist`)).status).toBe(404);
    });

    it('rejects non-GET/HEAD methods', async () => {
        const res = await fetch(`${BASE}/`, { method: 'POST' });
        expect(res.status).toBe(405);
        expect(res.headers.get('allow')).toBe('GET, HEAD');
    });
});

describe('static-server — malformed input must not kill the process', () => {
    // The original crash. `decodeURIComponent('%')` throws URIError; the call
    // sat outside any try block, so one request took the server down and every
    // subsequent test would have failed with a connection error.
    it('survives malformed percent-encoding', async () => {
        const res = await fetch(`${BASE}/%`);
        expect(res.status).toBe(404);
        expect(await isAlive()).toBe(true);
    });

    it.each([
        '/%E0%A4%A',      // truncated multi-byte sequence
        '/%ZZ',           // non-hex escape
        '/%00',           // NUL byte
        '/%2e%2e%2f%2e%2e%2fpackage.json',
        '/'.padEnd(4000, 'a'),
    ])('survives %s', async (path) => {
        const res = await fetch(`${BASE}${path}`).catch(() => null);
        // Any answer is acceptable; dying is not.
        expect(res === null || res.status >= 400).toBe(true);
        expect(await isAlive()).toBe(true);
    });
});

describe('static-server — nothing outside the served tree is reachable', () => {
    it.each([
        '/../package.json',
        '/../../etc/passwd',
        '/js/../../package.json',
        '/%2e%2e/package.json',
        '/%2e%2e%2fpackage.json',
        '/....//package.json',
        '/js/%2e%2e%2f%2e%2e%2fpackage.json',
    ])('refuses %s', async (path) => {
        const res = await fetch(`${BASE}${path}`);
        expect(res.status).toBe(404);
        // Belt and braces: even a 200 would be a failure if it leaked the file.
        if (res.status === 200) {
            expect(await res.text()).not.toContain('"name": "passflares"');
        }
    });

    it('does not serve repository files that sit outside public/', async () => {
        for (const path of ['/package.json', '/wrangler.toml', '/.dev.vars', '/src/auth.ts']) {
            expect((await fetch(`${BASE}${path}`)).status, path).toBe(404);
        }
    });
});
