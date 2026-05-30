// CRLF / header-injection regression tests.
//
// User-supplied bytes (Origin header, request bodies) must never appear
// verbatim in a response header. The Fetch standard's `Headers` API
// rejects raw CR/LF, so this is mostly a guard against future code that
// might use lower-level header construction.

import { describe, it, expect } from 'vitest';
import worker from '../../src/worker.js';
import { createMockEnv, mockCtx } from '../mocks/cloudflare.js';

function loginReq(headers: Record<string, string>, body: unknown = {}) {
    return new Request('https://passflares.test/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body)
    });
}

describe('Header injection — Origin header', () => {
    it('rejects an Origin with CRLF bytes (Fetch standard) without crashing the worker', async () => {
        // The Headers API throws on raw CR/LF — building the Request itself
        // should fail. If it ever doesn't, the worker must still not echo
        // the bytes into a response header.
        let req: Request | undefined;
        try {
            req = loginReq({ Origin: 'https://evil\r\nX-Injected: yes' });
        } catch {
            // expected — Headers rejected the value
            return;
        }
        // If we got here, the runtime accepted it. Make sure no rogue
        // header appears in the response.
        const res = await worker.fetch(req!, createMockEnv(), mockCtx);
        expect(res.headers.get('X-Injected')).toBeNull();
        for (const [name] of res.headers) {
            expect(name).not.toMatch(/\r|\n/);
        }
    });

    it('does not echo an oversize Origin value back into the response', async () => {
        const huge = 'https://evil.example/' + 'a'.repeat(8192);
        const res = await worker.fetch(loginReq({ Origin: huge }), createMockEnv(), mockCtx);
        expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe(huge);
    });

    it('does not echo a non-HTTPS Origin', async () => {
        const res = await worker.fetch(loginReq({ Origin: 'http://evil.example' }), createMockEnv(), mockCtx);
        expect(res.headers.get('Access-Control-Allow-Origin')).not.toBe('http://evil.example');
    });
});

describe('Header injection — request body', () => {
    it('a CRLF-laden email field does not surface in any response header', async () => {
        // We don't care whether the registration succeeds — we only care
        // that the response's headers don't carry the injected bytes.
        const res = await worker.fetch(
            loginReq({}, { email: "x@x\r\nX-Pwn: 1", password: 'whatever' }),
            createMockEnv(),
            mockCtx
        );
        for (const [name, value] of res.headers) {
            expect(name).not.toMatch(/\r|\n/);
            expect(value).not.toContain('X-Pwn');
        }
    });
});

describe('Header injection — response header sanity', () => {
    it('no response header value contains raw CR/LF', async () => {
        const res = await worker.fetch(loginReq({ Origin: 'https://passflares.com' }), createMockEnv(), mockCtx);
        for (const [, value] of res.headers) {
            expect(value).not.toMatch(/\r|\n/);
        }
    });
});
