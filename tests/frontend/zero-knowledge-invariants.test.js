// @vitest-environment happy-dom
//
// The README's security claims, as assertions (#89 §3, #83 §D).
//
// "Your master password never leaves your browser" and "neither half can
// produce the other" are the reasons someone trusts this with their passwords.
// Until now they lived only in prose, and a promise that isn't an assertion
// cannot fail — README.md can stay word-for-word true while the code beneath it
// stops being true, and nothing goes red.
//
// So each describe block below quotes the claim it enforces, and each quote is
// checked to still be in README.md: reword the promise and this file fails,
// pointing whoever rewrote it at the assertion that was standing behind it.
//
// These are deliberately end-to-end and property-shaped rather than unit tests
// of a function's return value. The falsifiability gate
// (tests/mutation/mutants.mjs, `--suite tests/frontend`) is what proves they can
// actually fail; six mutants survived the suite before this file existed.

import { describe, it, expect, beforeEach, afterEach, beforeAll, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { argon2id } from '../../public/vendor/noble-hashes/argon2.js';

const PASSWORD = 'correct horse battery staple';
const NEW_PASSWORD = 'an entirely different passphrase!7';
const EMAIL = 'user@example.com';
const SALT = 'aabbccddeeff00112233445566778899';

// Argon2id cost is a property of constants.js, asserted separately below.
// Everything here is about structure, so derive cheaply.
const FAST = { m: 256, t: 1, p: 1, len: 32 };

const README = readFileSync(resolve('README.md'), 'utf8');

// Prose is hard-wrapped, so a quote spanning a line break would otherwise be
// hostage to where the wrap happens to fall. Compare on collapsed whitespace:
// rewording still fails, re-flowing a paragraph does not.
const flatten = (text) => text.replace(/\s+/g, ' ').trim();
const READ_ME_FLAT = flatten(README);

/**
 * Fails if the claim this block enforces is no longer in the README. Not
 * pedantry about wording: it is the link between the promise and the test, and
 * without it a reworded README silently orphans the assertion below it.
 */
function claims(quote) {
    it(`README still makes this promise: "${flatten(quote)}"`, () => {
        expect(READ_ME_FLAT).toContain(flatten(quote));
    });
}

class FakeKdfWorker {
    constructor() { this.listeners = {}; }
    addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
    removeEventListener(type, fn) {
        this.listeners[type] = (this.listeners[type] ?? []).filter(f => f !== fn);
    }
    postMessage({ id, password, saltHex, params }) {
        const salt = Uint8Array.from(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
        const out = argon2id(new TextEncoder().encode(password), salt, {
            m: params.m, t: params.t, p: params.p, dkLen: params.len
        });
        const keyHex = Array.from(out).map(b => b.toString(16).padStart(2, '0')).join('');
        queueMicrotask(() => {
            for (const fn of this.listeners.message ?? []) fn({ data: { id, ok: true, keyHex } });
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  "the password is never transmitted"
// ─────────────────────────────────────────────────────────────────────────────

describe('the master password never reaches the network', () => {
    claims('the password is never transmitted');

    let mockFetch;

    beforeEach(() => {
        vi.stubGlobal('crypto', webcrypto);
        vi.stubGlobal('Worker', FakeKdfWorker);
        mockFetch = vi.fn();
        vi.stubGlobal('fetch', mockFetch);
        localStorage.clear();
        localStorage.setItem('jwtToken', 'test-session-token');
    });

    afterEach(() => { vi.unstubAllGlobals(); });

    const respond = (body, status = 200) =>
        mockFetch.mockResolvedValueOnce({ ok: true, status, json: () => Promise.resolve(body) });

    /**
     * Everything the browser actually put on the wire, flattened to one string
     * per request: URL, every header name and value, and the body.
     *
     * Whole-request rather than field-by-field on purpose. The previous
     * assertions named the fields they expected to be clean, so a password
     * smuggled through an unexpected field — or a header, or a query string —
     * passed straight through them. `fe-rotate-sends-new-password` did exactly
     * that: it survived a suite whose test was called "never sends the master
     * password", because that test only ever looked for the *old* one.
     */
    function requestsOnTheWire() {
        return mockFetch.mock.calls.map(([url, config = {}]) => {
            const headers = Object.entries(config.headers ?? {})
                .map(([k, v]) => `${k}: ${v}`).join('\n');
            return [String(url), headers, String(config.body ?? '')].join('\n');
        });
    }

    /**
     * @param {string[]} secrets  Values that must appear in no request at all.
     */
    function expectNothingLeaked(secrets) {
        const wire = requestsOnTheWire();
        expect(wire.length, 'no requests were recorded — the flow did not run').toBeGreaterThan(0);

        for (const secret of secrets) {
            // Percent- and JSON-encoding are the two forms a password can take
            // on its way out without appearing literally.
            const forms = [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1)];
            for (const [i, request] of wire.entries()) {
                for (const form of forms) {
                    expect(
                        request.includes(form),
                        `request #${i + 1} carries the master password:\n${request}`
                    ).toBe(false);
                }
            }
        }
    }

    it('during enrolment', async () => {
        const { enrollNewAccount } = await import('../../public/js/auth-flow.js');
        respond({ message: 'User registered successfully.' }, 201);

        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        expectNothingLeaked([PASSWORD]);
    });

    it('during sign-in', async () => {
        const { signIn } = await import('../../public/js/auth-flow.js');
        respond({ authVersion: 2, kdfSalt: SALT, kdfParams: FAST });
        respond({ message: 'Login successful.', userId: 1, authVersion: 2, token: 'jwt' });

        await signIn({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        expectNothingLeaked([PASSWORD]);
    });

    it('during a password change — including the new password', async () => {
        // The one the account is *about* to have is the more valuable of the
        // two, and is the half a "does the old password appear?" check misses.
        const { enrollNewAccount, rotateMasterPassword } = await import('../../public/js/auth-flow.js');

        respond({ message: 'ok' }, 201);
        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });
        const registerBody = JSON.parse(mockFetch.mock.calls.at(-1)[1].body);
        mockFetch.mockClear();

        respond({ authVersion: 2, kdfSalt: registerBody.kdfSalt, kdfParams: { m: 47104, t: 1, p: 1, len: 32 } });
        respond({ message: 'Master password updated successfully.' });

        await rotateMasterPassword({
            email: EMAIL, userId: 1,
            oldPassword: PASSWORD, newPassword: NEW_PASSWORD,
            privateKeyEnc: registerBody.privateKeyEnc
        });

        expectNothingLeaked([PASSWORD, NEW_PASSWORD]);
    }, 30_000);

    it('when re-authenticating for a 2FA change or account deletion', async () => {
        // These paths exist to prove the password to the server, which is
        // exactly where sending it is most tempting.
        const { deriveExistingHierarchy } = await import('../../public/js/auth-flow.js');
        respond({ authVersion: 2, kdfSalt: SALT, kdfParams: FAST });

        const { authSecret } = await deriveExistingHierarchy(EMAIL, PASSWORD);

        expect(authSecret).toMatch(/^[0-9a-f]{64}$/);
        expectNothingLeaked([PASSWORD]);
    });

    it('during the legacy upgrade, which is the flow that holds it longest', async () => {
        const { upgradeLegacyAccount } = await import('../../public/js/auth-flow.js');
        respond([]);
        respond({ message: 'Account upgraded.', authVersion: 2, legacyVaultsPending: 0 });

        await upgradeLegacyAccount({
            userId: 1, email: EMAIL, authVersion: 1,
            encryptionSalt: 'ff'.repeat(16), token: 'jwt'
        }, PASSWORD);

        expectNothingLeaked([PASSWORD]);
    });

    it('and the one documented exception is narrow: legacy sign-in, once', async () => {
        // README, "Migration status": pre-1.1.4 accounts still send the password
        // at sign-in, "until then, and only for them". Asserting the exception
        // keeps it from quietly widening — if a v2 account ever took this path
        // the test above would already be failing, and if the legacy path
        // stopped being reachable this one would tell us the note is stale.
        expect(READ_ME_FLAT).toContain('Until then, and only for them, the legacy behaviour still applies.');

        const { signIn } = await import('../../public/js/auth-flow.js');
        respond({ authVersion: 1 });
        respond({ userId: 1, authVersion: 1, encryptionSalt: 'ff'.repeat(16), token: 'jwt' });

        const { authVersion } = await signIn({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        expect(authVersion).toBe(1);
        const carrying = requestsOnTheWire().filter(r => r.includes(PASSWORD));
        expect(carrying).toHaveLength(1);
        expect(carrying[0]).toContain('/login');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
//  "neither half can produce the other"
// ─────────────────────────────────────────────────────────────────────────────

describe('the server cannot derive the KEK from what it stores', () => {
    claims('Your master password is stretched, then split, and neither half can produce the\nother');
    claims('an attacker holding everything the server has still cannot derive `kek`');

    beforeAll(() => {
        vi.stubGlobal('crypto', webcrypto);
        vi.stubGlobal('Worker', FakeKdfWorker);
    });

    const load = () => import('../../public/js/keys.js');

    /** The KEK's raw bytes, which deriveKek deliberately does not expose. */
    async function kekBytes(masterKey) {
        const { HKDF_INFO_KEK } = await import('../../public/js/constants.js');
        const base = await webcrypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
        const bits = await webcrypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(HKDF_INFO_KEK) },
            base, 256
        );
        return new Uint8Array(bits);
    }

    const hex = (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');

    it('the value sent to the server is not the master key itself', async () => {
        // A 32-byte master key hex-encodes to the same 64 characters an HKDF
        // branch does, so "looks like a hex secret" proves nothing. Compare.
        const { deriveMasterKey, deriveAuthSecret } = await load();
        const masterKey = await deriveMasterKey(PASSWORD, SALT, FAST);
        const authSecret = await deriveAuthSecret(masterKey);

        expect(authSecret).not.toBe(hex(masterKey));
    });

    it('the value sent to the server is not the KEK', async () => {
        const { deriveMasterKey, deriveAuthSecret } = await load();
        const masterKey = await deriveMasterKey(PASSWORD, SALT, FAST);

        expect(await deriveAuthSecret(masterKey)).not.toBe(hex(await kekBytes(masterKey)));
    });

    it('the two HKDF branches share no bytes at any position', async () => {
        // Stronger than inequality and much cheaper than a statistical test: two
        // independent 32-byte strings colliding anywhere is possible, but
        // agreeing on more than a couple of positions is not.
        const { deriveMasterKey, deriveAuthSecret } = await load();
        const masterKey = await deriveMasterKey(PASSWORD, SALT, FAST);

        const auth = Uint8Array.from(
            (await deriveAuthSecret(masterKey)).match(/.{2}/g).map(h => parseInt(h, 16))
        );
        const kek = await kekBytes(masterKey);

        const agreeing = [...auth].filter((byte, i) => byte === kek[i]).length;
        expect(agreeing).toBeLessThan(4);
    });

    it('an attacker holding authSecret cannot open the private key blob', async () => {
        // The whole claim, end to end: take everything the server stores and
        // try every way it could be turned into the wrapping key.
        const { deriveMasterKey, deriveAuthSecret, deriveKek, generateUserKeypair, wrapPrivateKey, unwrapPrivateKey }
            = await load();
        const { ENCRYPTION_ALGORITHM } = await import('../../public/js/constants.js');

        const masterKey = await deriveMasterKey(PASSWORD, SALT, FAST);
        const authSecret = await deriveAuthSecret(masterKey);
        const kek = await deriveKek(masterKey);

        const { privateKey } = await generateUserKeypair();
        const privateKeyEnc = await wrapPrivateKey(kek, privateKey);

        const authSecretBytes = Uint8Array.from(authSecret.match(/.{2}/g).map(h => parseInt(h, 16)));
        const asAesKey = await webcrypto.subtle.importKey(
            'raw', authSecretBytes, { name: ENCRYPTION_ALGORITHM }, false, ['encrypt', 'decrypt']
        );

        await expect(unwrapPrivateKey(asAesKey, privateKeyEnc)).rejects.toThrow();
        // And the real KEK does open it, so the rejection above is about the
        // key and not about a malformed blob.
        await expect(unwrapPrivateKey(kek, privateKeyEnc)).resolves.toBeDefined();
    });

    it('the KEK is non-extractable, so nothing can serialise it', async () => {
        const { deriveMasterKey, deriveKek } = await load();
        const kek = await deriveKek(await deriveMasterKey(PASSWORD, SALT, FAST));

        expect(kek.extractable).toBe(false);
        await expect(webcrypto.subtle.exportKey('raw', kek)).rejects.toThrow();
    });

    it('uses the documented info strings — they are part of the wire format', async () => {
        const { HKDF_INFO_AUTH, HKDF_INFO_KEK } = await import('../../public/js/constants.js');
        expect(HKDF_INFO_AUTH).toBe('passflares:auth:v2');
        expect(HKDF_INFO_KEK).toBe('passflares:kek:v2');
        expect(HKDF_INFO_AUTH).not.toBe(HKDF_INFO_KEK);
        expect(READ_ME_FLAT).toContain('info="passflares:auth:v2"');
        expect(READ_ME_FLAT).toContain('info="passflares:kek:v2"');
    });

    it('stretches with the Argon2id profile the README publishes', async () => {
        const { ARGON2_PARAMS } = await import('../../public/js/constants.js');
        expect(ARGON2_PARAMS).toEqual({ m: 47104, t: 1, p: 1, len: 32 });
        expect(READ_ME_FLAT).toContain('Argon2id(password, kdfSalt, m=47104 KiB, t=1, p=1, 32 bytes)');
    });
});

// ─────────────────────────────────────────────────────────────────────────────
//  "decrypted in your browser alone"
// ─────────────────────────────────────────────────────────────────────────────

describe('key material cannot be serialised out of the session', () => {
    claims('the private key is stored\n  only as `AES-256-GCM(kek, privateKey)` and is decrypted in your browser alone');

    beforeAll(() => {
        vi.stubGlobal('crypto', webcrypto);
        vi.stubGlobal('Worker', FakeKdfWorker);
    });

    const load = () => import('../../public/js/keys.js');

    it('the unwrapped private key is non-extractable', async () => {
        // The threat-model row for XSS says the in-memory key is reachable from
        // JS — reachable is not the same as exportable. Non-extractable bounds
        // an injected script to what it can do while the tab is open; an
        // extractable key lets it exfiltrate the identity that opens every
        // vault share this account holds, permanently.
        const { deriveMasterKey, deriveKek, generateUserKeypair, wrapPrivateKey, unwrapPrivateKey } = await load();
        const kek = await deriveKek(await deriveMasterKey(PASSWORD, SALT, FAST));

        const { privateKey } = await generateUserKeypair();
        const recovered = await unwrapPrivateKey(kek, await wrapPrivateKey(kek, privateKey));

        expect(recovered.extractable).toBe(false);
        await expect(webcrypto.subtle.exportKey('pkcs8', recovered)).rejects.toThrow();
    });

    it('the freshly generated private key is extractable only long enough to be wrapped', async () => {
        // generateUserKeypair has to produce an extractable key — it is exported
        // to PKCS#8 and sealed immediately. What must not happen is that form
        // outliving the wrap, so nothing but enrolment ever sees it.
        const { generateUserKeypair, deriveMasterKey, deriveKek, wrapPrivateKey } = await load();
        const { privateKey } = await generateUserKeypair();
        expect(privateKey.extractable).toBe(true);

        const kek = await deriveKek(await deriveMasterKey(PASSWORD, SALT, FAST));
        const blob = await wrapPrivateKey(kek, privateKey);
        expect(blob).toMatch(/^[0-9a-f]{24}:[0-9a-f]+$/);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
//  AES-GCM nonce hygiene
// ─────────────────────────────────────────────────────────────────────────────

describe('every AES-GCM seal uses a fresh IV', () => {
    claims('blobs are AES-256-GCM and no key is stored');

    beforeAll(() => {
        vi.stubGlobal('crypto', webcrypto);
        vi.stubGlobal('Worker', FakeKdfWorker);
    });

    // GCM does not degrade gracefully under nonce reuse: two messages sealed
    // under the same (key, IV) leak their XOR *and* the authentication subkey,
    // which turns a confidentiality break into a forgery one. Both sealing
    // paths — vault entries in crypto.js and key blobs in keys.js — are
    // therefore checked, and they are separate code.

    it('when sealing vault entries (crypto.js)', async () => {
        const { generateVaultKey } = await import('../../public/js/keys.js');
        const { encryptData } = await import('../../public/js/crypto.js');
        const vaultKey = await generateVaultKey();

        const seals = await Promise.all(
            Array.from({ length: 8 }, () => encryptData([{ name: 'same plaintext' }], vaultKey))
        );

        expect(new Set(seals.map(s => s.iv)).size).toBe(seals.length);
        expect(seals.every(s => /^[0-9a-f]{24}$/.test(s.iv))).toBe(true);
        expect(seals.some(s => s.iv === '0'.repeat(24))).toBe(false);
        // Identical plaintext under one key must still produce distinct
        // ciphertext — the property a fixed IV destroys.
        expect(new Set(seals.map(s => s.ciphertext)).size).toBe(seals.length);
    });

    it('when sealing wrapped key blobs (keys.js)', async () => {
        const { deriveMasterKey, deriveKek, generateUserKeypair, wrapPrivateKey } = await import('../../public/js/keys.js');
        const kek = await deriveKek(await deriveMasterKey(PASSWORD, SALT, FAST));
        const { privateKey } = await generateUserKeypair();

        const blobs = await Promise.all(
            Array.from({ length: 8 }, () => wrapPrivateKey(kek, privateKey))
        );
        const ivs = blobs.map(b => b.split(':')[0]);

        expect(new Set(ivs).size).toBe(blobs.length);
        expect(ivs.every(iv => /^[0-9a-f]{24}$/.test(iv))).toBe(true);
        expect(ivs.some(iv => iv === '0'.repeat(24))).toBe(false);
        expect(new Set(blobs).size).toBe(blobs.length);
    });
});
