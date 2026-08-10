import { describe, it, expect, vi, afterEach } from 'vitest';
import {
    uint8ArrayToHexString,
    hexStringToUint8Array,
    jsonResponse,
    deriveScryptHash,
    verifyTurnstile,
    timingSafeEqualHex,
    parseId,
    parseCounter,
    normalizeEmail,
    isValidEmail,
    decoyKdfSalt
} from '../../src/utils.js';

describe('uint8ArrayToHexString', () => {
    it('converts a known byte array to hex', () => {
        const input = new Uint8Array([0, 1, 15, 16, 255]);
        expect(uint8ArrayToHexString(input)).toBe('00010f10ff');
    });

    it('returns an empty string for an empty array', () => {
        expect(uint8ArrayToHexString(new Uint8Array([]))).toBe('');
    });
});

describe('hexStringToUint8Array', () => {
    it('converts a hex string back to the original bytes', () => {
        const hex = '00010f10ff';
        const result = hexStringToUint8Array(hex);
        expect(Array.from(result)).toEqual([0, 1, 15, 16, 255]);
    });

    it('throws on an odd-length hex string', () => {
        expect(() => hexStringToUint8Array('abc')).toThrow();
    });

    it('is the inverse of uint8ArrayToHexString', () => {
        const original = new Uint8Array([42, 99, 200, 0, 7]);
        const roundtrip = hexStringToUint8Array(uint8ArrayToHexString(original));
        expect(Array.from(roundtrip)).toEqual(Array.from(original));
    });
});

describe('jsonResponse', () => {
    it('returns a 200 response with JSON body by default', async () => {
        const res = jsonResponse({ message: 'ok' });
        expect(res.status).toBe(200);
        expect(res.headers.get('Content-Type')).toBe('application/json');
        const body = await res.json();
        expect(body).toEqual({ message: 'ok' });
    });

    it('respects a custom status code', async () => {
        const res = jsonResponse({ message: 'created' }, 201);
        expect(res.status).toBe(201);
    });

    it('returns correct body for a 400 error', async () => {
        const res = jsonResponse({ message: 'bad request' }, 400);
        const body = await res.json();
        expect(body.message).toBe('bad request');
    });
});

describe('deriveScryptHash', () => {
    it('returns a hash and a salt as hex strings', async () => {
        const { hash, salt } = await deriveScryptHash('password123');
        expect(hash).toMatch(/^[0-9a-f]+$/);
        expect(salt).toMatch(/^[0-9a-f]+$/);
    }, 30_000);

    it('produces the same hash when given the same salt', async () => {
        const { hash: hash1, salt } = await deriveScryptHash('mypassword');
        const { hash: hash2 } = await deriveScryptHash('mypassword', salt);
        expect(hash1).toBe(hash2);
    }, 30_000);

    it('produces different hashes for different passwords', async () => {
        const { hash: hash1, salt } = await deriveScryptHash('password-A');
        const { hash: hash2 } = await deriveScryptHash('password-B', salt);
        expect(hash1).not.toBe(hash2);
    }, 30_000);
}, 60_000);

describe('verifyTurnstile', () => {
    afterEach(() => vi.unstubAllGlobals());

    function stubFetch(body: unknown, status = 200) {
        vi.stubGlobal('fetch', vi.fn(async () =>
            new Response(JSON.stringify(body), {
                status,
                headers: { 'Content-Type': 'application/json' }
            })
        ));
    }

    it('returns true when Cloudflare reports success', async () => {
        stubFetch({ success: true });
        expect(await verifyTurnstile('token', 'secret')).toBe(true);
    });

    it('returns false when Cloudflare reports failure', async () => {
        stubFetch({ success: false, 'error-codes': ['invalid-input-response'] });
        expect(await verifyTurnstile('token', 'secret')).toBe(false);
    });

    it('returns false when the token is missing', async () => {
        stubFetch({ success: true });
        expect(await verifyTurnstile(null, 'secret')).toBe(false);
        expect(await verifyTurnstile(undefined, 'secret')).toBe(false);
        expect(await verifyTurnstile('', 'secret')).toBe(false);
    });

    it('returns false when the secret is missing', async () => {
        stubFetch({ success: true });
        expect(await verifyTurnstile('token', '')).toBe(false);
    });

    it('returns false when the siteverify endpoint returns a non-2xx', async () => {
        // The body deliberately claims success. With `{}` this test passed
        // whether or not the `!result.ok` guard existed — `data.success` was
        // undefined either way, so it was green for the wrong reason and
        // deleting the guard changed nothing. Now only the status check can
        // produce `false`, so the assertion is about the guard it names.
        stubFetch({ success: true }, 500);
        expect(await verifyTurnstile('token', 'secret')).toBe(false);
    });

    it('returns false when fetch throws', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network'); }));
        expect(await verifyTurnstile('token', 'secret')).toBe(false);
    });

    // Everything above asserts the return value, so the request itself was
    // never checked: sending an empty secret, or dropping the token, kept the
    // suite green. Cloudflare fails such a request closed, which makes this an
    // availability bug rather than a bypass — every human would be told they
    // are a bot — but nothing here could tell you it had happened.
    it('sends the secret, the token and the caller IP to siteverify', async () => {
        const fetchMock = vi.fn(async () =>
            new Response(JSON.stringify({ success: true }), {
                status: 200, headers: { 'Content-Type': 'application/json' }
            })
        );
        vi.stubGlobal('fetch', fetchMock);

        await verifyTurnstile('the-token', 'the-secret', '203.0.113.7');

        const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
        expect(url).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify');
        expect(init.method).toBe('POST');

        const form = init.body as FormData;
        expect(form.get('secret')).toBe('the-secret');
        expect(form.get('response')).toBe('the-token');
        expect(form.get('remoteip')).toBe('203.0.113.7');
    });

    it('omits remoteip when no caller IP is available', async () => {
        // Cloudflare rejects an empty remoteip rather than ignoring it, so
        // "absent" and "present but blank" are not the same request.
        const fetchMock = vi.fn(async () =>
            new Response(JSON.stringify({ success: true }), {
                status: 200, headers: { 'Content-Type': 'application/json' }
            })
        );
        vi.stubGlobal('fetch', fetchMock);

        await verifyTurnstile('the-token', 'the-secret', null);

        const form = (fetchMock.mock.calls[0] as [string, RequestInit])[1].body as FormData;
        expect(form.get('remoteip')).toBeNull();
    });
});

// --- timingSafeEqualHex (GHSA-jrh6-9qp8-rfgf) ---

describe('timingSafeEqualHex', () => {
    const HASH = 'deadbeefdeadbeefdeadbeefdeadbeef';

    it('accepts identical hex digests', () => {
        expect(timingSafeEqualHex(HASH, HASH)).toBe(true);
    });

    it('rejects a digest differing only in the final byte', () => {
        // The case a short-circuiting `!==` would answer fastest.
        expect(timingSafeEqualHex(HASH, 'deadbeefdeadbeefdeadbeefdeadbeff')).toBe(false);
    });

    it('rejects a digest differing only in the first byte', () => {
        expect(timingSafeEqualHex(HASH, 'aeadbeefdeadbeefdeadbeefdeadbeef')).toBe(false);
    });

    it('is case-sensitive about encoding but not about value', () => {
        // hexStringToUint8Array decodes both cases, so 'DE' and 'de' are equal
        // bytes — which is correct, they are the same digest.
        expect(timingSafeEqualHex('deadbeef', 'DEADBEEF')).toBe(true);
    });

    it('fails closed on malformed or mismatched input instead of throwing', () => {
        expect(timingSafeEqualHex(HASH, '')).toBe(false);
        expect(timingSafeEqualHex('', '')).toBe(false);
        expect(timingSafeEqualHex(HASH, HASH + 'aa')).toBe(false);
        expect(timingSafeEqualHex('zz', 'zz')).toBe(false);
        expect(timingSafeEqualHex(null as any, HASH)).toBe(false);
        expect(timingSafeEqualHex(undefined as any, undefined as any)).toBe(false);
    });
});

// --- parseId (#80) ---

describe('parseId', () => {
    it('accepts a plain positive decimal id', () => {
        expect(parseId('1')).toBe(1);
        expect(parseId('4242')).toBe(4242);
    });

    it('rejects the coercion surprises that make two URLs address one row', () => {
        // parseInt('12abc', 10) === 12 and Number('0x10') === 16 — either would
        // let /vaults/0x10 and /vaults/16 be the same vault.
        expect(parseId('0x10')).toBeNull();
        expect(parseId('12abc')).toBeNull();
        expect(parseId('1e3')).toBeNull();
        expect(parseId(' 1 ')).toBeNull();
        expect(parseId('1.5')).toBeNull();
        expect(parseId('+1')).toBeNull();
    });

    it('rejects zero, negatives and non-strings', () => {
        expect(parseId('0')).toBeNull();
        expect(parseId('-1')).toBeNull();
        expect(parseId('')).toBeNull();
        expect(parseId(undefined)).toBeNull();
        expect(parseId(null)).toBeNull();
    });

    it('rejects ids beyond safe integer precision', () => {
        expect(parseId('9007199254740993')).toBeNull();
    });
});

// --- parseCounter ---

describe('parseCounter', () => {
    it('reads a stored KV counter', () => {
        expect(parseCounter('5')).toBe(5);
    });

    it('treats anything unparseable as zero so rate limiting fails open, not closed', () => {
        expect(parseCounter(null)).toBe(0);
        expect(parseCounter(undefined)).toBe(0);
        expect(parseCounter('')).toBe(0);
        expect(parseCounter('abc')).toBe(0);
        expect(parseCounter('-3')).toBe(0);
    });
});

// --- email normalisation (#80) ---

describe('normalizeEmail / isValidEmail', () => {
    it('lowercases and trims, so one address is one account', () => {
        // SQLite UNIQUE is case-sensitive; without this, Foo@example.com and
        // foo@example.com are two accounts with two separate vault sets.
        expect(normalizeEmail('  Foo@Example.COM ')).toBe('foo@example.com');
    });

    it('returns an empty string for non-strings', () => {
        expect(normalizeEmail(undefined)).toBe('');
        expect(normalizeEmail(null)).toBe('');
        expect(normalizeEmail(42)).toBe('');
    });

    it('accepts ordinary addresses', () => {
        expect(isValidEmail('user@example.com')).toBe(true);
        expect(isValidEmail('first.last+tag@sub.example.co.uk')).toBe(true);
    });

    it('rejects what the browser type="email" check would have caught', () => {
        // That check was the only validation, and calling the API directly
        // bypassed it entirely.
        expect(isValidEmail('not an email')).toBe(false);
        expect(isValidEmail('no-at-sign.com')).toBe(false);
        expect(isValidEmail('user@nodot')).toBe(false);
        expect(isValidEmail('user@@example.com')).toBe(false);
        expect(isValidEmail('a@b.c' + 'd'.repeat(300))).toBe(false);
    });
});

// --- decoyKdfSalt ---

describe('decoyKdfSalt', () => {
    it('is stable for the same email, so retries look consistent', () => {
        // An unstable decoy would itself be the oracle: a real account's salt
        // never changes between calls.
        expect(decoyKdfSalt('a@b.com', 'secret')).toBe(decoyKdfSalt('a@b.com', 'secret'));
    });

    it('differs per email and per server secret', () => {
        expect(decoyKdfSalt('a@b.com', 'secret')).not.toBe(decoyKdfSalt('c@d.com', 'secret'));
        expect(decoyKdfSalt('a@b.com', 'secret')).not.toBe(decoyKdfSalt('a@b.com', 'other'));
    });

    it('is indistinguishable in shape from a real salt', () => {
        expect(decoyKdfSalt('a@b.com', 'secret')).toMatch(/^[0-9a-f]{32}$/);
    });
});
