// @vitest-environment happy-dom
//
// What actually goes on the wire.
//
// GHSA-pqm6-r3vj-mhvq is closed exactly when the master password stops reaching
// the worker. That is a property of these request bodies, so it is asserted
// here directly: every payload is inspected for the password itself.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { argon2id } from '../../public/vendor/noble-hashes/argon2.js';

const PASSWORD = 'correct horse battery staple';
const EMAIL = 'user@example.com';
const FAST_PARAMS = { m: 256, t: 1, p: 1, len: 32 };

let mockFetch;

beforeEach(() => {
    vi.stubGlobal('crypto', webcrypto);
    vi.stubGlobal('Worker', class FakeKdfWorker {
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
    });
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    localStorage.clear();
    // The upgrade and rotation paths call authenticated endpoints, which read
    // the session token from storage.
    localStorage.setItem('jwtToken', 'test-session-token');
});

afterEach(() => {
    vi.unstubAllGlobals();
});

function respond(body, status = 200) {
    mockFetch.mockResolvedValueOnce({ ok: true, status, json: () => Promise.resolve(body) });
}

/** Every request body this test recorded, parsed. */
function sentBodies() {
    return mockFetch.mock.calls
        .map(([, config]) => config?.body)
        .filter(Boolean)
        .map(b => JSON.parse(b));
}

// Matches on method too: a vault endpoint is hit by both a GET (no body) and a
// PUT, and the GET would otherwise shadow the request under test.
function bodyOf(endpoint, method) {
    const call = mockFetch.mock.calls.find(([url, config]) =>
        url.includes(endpoint) && (!method || config?.method === method) && config?.body
    );
    return call?.[1]?.body ? JSON.parse(call[1].body) : null;
}

describe('registration', () => {
    it('never sends the master password', async () => {
        const { enrollNewAccount } = await import('../../public/js/auth-flow.js');
        respond({ message: 'User registered successfully.' }, 201);

        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        const body = bodyOf('/register');
        expect(body.email).toBe(EMAIL);
        expect(body.authSecret).toMatch(/^[0-9a-f]{64}$/);
        expect(body.kdfSalt).toMatch(/^[0-9a-f]{32}$/);
        expect(body.publicKey).toBeTruthy();
        expect(body.privateKeyEnc).toMatch(/^[0-9a-f]+:[0-9a-f]+$/);

        // The decisive assertion.
        expect(JSON.stringify(body)).not.toContain(PASSWORD);
        expect(body.masterPassword).toBeUndefined();
        expect(body.encryptionSalt).toBeUndefined();
    });

    it('seals the private key so the server receives only ciphertext', async () => {
        const { enrollNewAccount } = await import('../../public/js/auth-flow.js');
        respond({ message: 'ok' }, 201);
        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        const { privateKeyEnc, publicKey } = bodyOf('/register');
        // A PKCS#8 P-256 private key is ~138 bytes; the sealed form must not be
        // recognisable as, or equal to, the public half.
        expect(privateKeyEnc).not.toContain(publicKey);
    });
});

describe('sign-in', () => {
    it('sends an auth secret, never the password, for an upgraded account', async () => {
        const { signIn } = await import('../../public/js/auth-flow.js');
        respond({ authVersion: 2, kdfSalt: 'ab'.repeat(16), kdfParams: FAST_PARAMS });
        respond({ message: 'Login successful.', userId: 1, email: EMAIL, authVersion: 2, token: 'jwt' });

        const { response, authVersion } = await signIn({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        expect(authVersion).toBe(2);
        expect(response.token).toBe('jwt');

        const body = bodyOf('/login');
        expect(body.authSecret).toMatch(/^[0-9a-f]{64}$/);
        expect(body.masterPassword).toBeUndefined();
        expect(JSON.stringify(sentBodies())).not.toContain(PASSWORD);
    });

    it('derives the same auth secret on every sign-in', async () => {
        const { signIn } = await import('../../public/js/auth-flow.js');
        const params = { authVersion: 2, kdfSalt: 'ab'.repeat(16), kdfParams: FAST_PARAMS };

        respond(params); respond({ token: 'a', authVersion: 2 });
        await signIn({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });
        const first = bodyOf('/login').authSecret;

        mockFetch.mockClear();
        respond(params); respond({ token: 'b', authVersion: 2 });
        await signIn({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        expect(bodyOf('/login').authSecret).toBe(first);
    });

    it('falls back to the legacy flow only for an unmigrated account', async () => {
        // The one remaining path where the password crosses the wire, and only
        // until the account finishes upgrading moments later.
        const { signIn } = await import('../../public/js/auth-flow.js');
        respond({ authVersion: 1 });
        respond({ userId: 1, email: EMAIL, authVersion: 1, encryptionSalt: 'ff'.repeat(16), token: 'jwt' });

        const { authVersion } = await signIn({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        expect(authVersion).toBe(1);
        expect(bodyOf('/login').masterPassword).toBe(PASSWORD);
    });

    it('asks for auth params before deciding which flow to run', async () => {
        const { signIn } = await import('../../public/js/auth-flow.js');
        respond({ authVersion: 2, kdfSalt: 'ab'.repeat(16), kdfParams: FAST_PARAMS });
        respond({ token: 'jwt', authVersion: 2 });

        await signIn({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });

        expect(mockFetch.mock.calls[0][0]).toContain('/auth/params');
        expect(mockFetch.mock.calls[0][0]).toContain(encodeURIComponent(EMAIL));
    });
});

describe('legacy account upgrade', () => {
    const LOGIN_RESPONSE = {
        userId: 1, email: EMAIL, authVersion: 1,
        encryptionSalt: 'ff'.repeat(16), token: 'jwt'
    };

    it('re-keys owned vaults, stages the blobs, and commits in one request', async () => {
        const { upgradeLegacyAccount } = await import('../../public/js/auth-flow.js');
        const { deriveLegacyKey, encryptData } = await import('../../public/js/crypto.js');

        const entries = [{ name: 'GitHub', username: 'pierre', password: 'hunter2' }];
        const legacyKey = await deriveLegacyKey(PASSWORD, LOGIN_RESPONSE.encryptionSalt);
        const legacyBlob = await encryptData(entries, legacyKey);

        respond([{ id: 7, name: 'Personal', owner_type: 'user', permission_level: 'manage' }]);
        respond({ encryptedData: legacyBlob });
        respond({ message: 'Staged.', keyVersion: 'v2', staged: true });
        respond({ message: 'Account upgraded.', authVersion: 2, legacyVaultsPending: 0 });

        const result = await upgradeLegacyAccount(LOGIN_RESPONSE, PASSWORD);
        expect(result.vaultsRekeyed).toBe(1);

        // The re-encrypted blob is staged under v2 rather than overwriting the
        // live one — nothing readable is destroyed before the server commits.
        expect(bodyOf('/vaults/7/data', 'PUT').keyVersion).toBe('v2');

        const upgrade = bodyOf('/auth/upgrade');
        expect(upgrade.vaults).toHaveLength(1);
        expect(upgrade.vaults[0].vaultId).toBe(7);
        expect(upgrade.authSecret).toMatch(/^[0-9a-f]{64}$/);
        expect(JSON.stringify(upgrade)).not.toContain(PASSWORD);
    });

    it('skips organisation vaults — re-keying one would lock out every other member', async () => {
        const { upgradeLegacyAccount } = await import('../../public/js/auth-flow.js');

        respond([
            { id: 7, name: 'Personal', owner_type: 'user', permission_level: 'manage' },
            { id: 8, name: 'Team', owner_type: 'organization', permission_level: 'manage' },
            { id: 9, name: 'ReadOnly', owner_type: 'organization', permission_level: 'read' }
        ]);
        respond(null);  // vault 7 is empty
        respond({ message: 'Staged.', staged: true });
        respond({ message: 'Account upgraded.', authVersion: 2, legacyVaultsPending: 2 });

        const result = await upgradeLegacyAccount(LOGIN_RESPONSE, PASSWORD);

        expect(result.vaultsRekeyed).toBe(1);
        expect(bodyOf('/auth/upgrade').vaults.map(v => v.vaultId)).toEqual([7]);
        // Read-only org vaults are exactly what used to 403 halfway through the
        // old password-change loop and corrupt everything written before it.
        expect(mockFetch.mock.calls.some(([url]) => url.includes('/vaults/9/data'))).toBe(false);
    });

    it('aborts without committing when a vault cannot be decrypted', async () => {
        // Leaves the account wholly on v1 with its original blobs live. The
        // staged .v2 objects are orphaned but inert — nothing reads them until
        // current_key_version says so.
        const { upgradeLegacyAccount } = await import('../../public/js/auth-flow.js');

        respond([{ id: 7, name: 'Corrupt', owner_type: 'user', permission_level: 'manage' }]);
        respond({ encryptedData: { iv: 'aa'.repeat(12), ciphertext: 'bb'.repeat(40) } });

        await expect(upgradeLegacyAccount(LOGIN_RESPONSE, PASSWORD))
            .rejects.toThrow(/could not be re-encrypted/i);

        expect(mockFetch.mock.calls.some(([url]) => url.includes('/auth/upgrade'))).toBe(false);
    });

    it('keeps the legacy key when org vaults still need rescuing', async () => {
        const { upgradeLegacyAccount } = await import('../../public/js/auth-flow.js');
        const { getLegacyKey } = await import('../../public/js/state.js');

        respond([]);
        respond({ message: 'Account upgraded.', authVersion: 2, legacyVaultsPending: 2 });

        await upgradeLegacyAccount(LOGIN_RESPONSE, PASSWORD);
        // Only this key can decrypt org vaults created before the hierarchy, and
        // only their creator ever had it (#69).
        expect(getLegacyKey()).not.toBeNull();
    });

    it('discards the legacy key once nothing needs it', async () => {
        const { upgradeLegacyAccount } = await import('../../public/js/auth-flow.js');
        const { getLegacyKey, reset } = await import('../../public/js/state.js');
        reset();

        respond([]);
        respond({ message: 'Account upgraded.', authVersion: 2, legacyVaultsPending: 0 });

        await upgradeLegacyAccount(LOGIN_RESPONSE, PASSWORD);
        expect(getLegacyKey()).toBeNull();
    });
});

describe('master password rotation (#70)', () => {
    it('re-seals one key blob and never touches vault ciphertext', { timeout: 30_000 }, async () => {
        const { enrollNewAccount, rotateMasterPassword } = await import('../../public/js/auth-flow.js');

        respond({ message: 'ok' }, 201);
        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });
        const { privateKeyEnc, kdfSalt } = bodyOf('/register');
        mockFetch.mockClear();

        respond({ authVersion: 2, kdfSalt, kdfParams: { m: 47104, t: 1, p: 1, len: 32 } });
        respond({ message: 'Master password updated successfully.' });

        const result = await rotateMasterPassword({
            email: EMAIL, userId: 1,
            oldPassword: PASSWORD, newPassword: 'a whole new passphrase!1',
            privateKeyEnc
        });

        // No vault was listed, downloaded, or written. The old flow re-encrypted
        // every vault and could corrupt them all if interrupted.
        expect(mockFetch.mock.calls.some(([url]) => url.includes('/vaults'))).toBe(false);

        const body = bodyOf('/update-password');
        expect(body.oldAuthSecret).toMatch(/^[0-9a-f]{64}$/);
        expect(body.newAuthSecret).toMatch(/^[0-9a-f]{64}$/);
        expect(body.oldAuthSecret).not.toBe(body.newAuthSecret);
        expect(body.newPrivateKeyEnc).not.toBe(privateKeyEnc);
        expect(result.privateKeyEnc).toBe(body.newPrivateKeyEnc);

        expect(JSON.stringify(body)).not.toContain(PASSWORD);
    });

    it('rejects a wrong current password locally, before any request', { timeout: 30_000 }, async () => {
        const { enrollNewAccount, rotateMasterPassword } = await import('../../public/js/auth-flow.js');

        respond({ message: 'ok' }, 201);
        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });
        const { privateKeyEnc, kdfSalt } = bodyOf('/register');
        mockFetch.mockClear();

        respond({ authVersion: 2, kdfSalt, kdfParams: { m: 47104, t: 1, p: 1, len: 32 } });

        await expect(rotateMasterPassword({
            email: EMAIL, userId: 1,
            oldPassword: 'wrong password entirely', newPassword: 'a whole new passphrase!1',
            privateKeyEnc
        })).rejects.toThrow(/incorrect/i);

        expect(mockFetch.mock.calls.some(([url]) => url.includes('/update-password'))).toBe(false);
    });

    it('produces a blob the new password can open and the old one cannot', { timeout: 30_000 }, async () => {
        const { enrollNewAccount, rotateMasterPassword, deriveExistingHierarchy } =
            await import('../../public/js/auth-flow.js');
        const { unwrapPrivateKey } = await import('../../public/js/keys.js');

        respond({ message: 'ok' }, 201);
        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });
        const { privateKeyEnc, kdfSalt } = bodyOf('/register');
        const params = { authVersion: 2, kdfSalt, kdfParams: { m: 47104, t: 1, p: 1, len: 32 } };
        mockFetch.mockClear();

        const NEW_PASSWORD = 'a whole new passphrase!1';
        respond(params);
        respond({ message: 'ok' });
        const rotated = await rotateMasterPassword({
            email: EMAIL, userId: 1, oldPassword: PASSWORD, newPassword: NEW_PASSWORD, privateKeyEnc
        });

        const newParams = { authVersion: 2, kdfSalt: rotated.kdfSalt, kdfParams: rotated.kdfParams };
        respond(newParams);
        const { kek: newKek } = await deriveExistingHierarchy(EMAIL, NEW_PASSWORD);
        await expect(unwrapPrivateKey(newKek, rotated.privateKeyEnc)).resolves.toBeDefined();

        respond(newParams);
        const { kek: oldKek } = await deriveExistingHierarchy(EMAIL, PASSWORD);
        await expect(unwrapPrivateKey(oldKek, rotated.privateKeyEnc)).rejects.toThrow();
    });
});

describe('nothing sensitive is persisted', () => {
    // CodeQL, not this suite, caught privateKeyEnc being written to
    // localStorage. It was ciphertext the server already held, so the practical
    // exposure was nil — but persisting it bought nothing either, since a reload
    // clears the in-memory private key and forces a fresh sign-in anyway.
    //
    // These assertions pin the rule rather than the one instance: after any
    // auth operation, storage must contain nothing that helps an attacker who
    // has scraped it.
    const FORBIDDEN = [
        ['the master password', () => PASSWORD],
        ['a derived auth secret', (bodies) => bodies.find(b => b.authSecret)?.authSecret],
        ['the sealed private key', (bodies) => bodies.find(b => b.privateKeyEnc)?.privateKeyEnc]
    ];

    function assertStorageClean(bodies) {
        const dump = JSON.stringify(localStorage);
        for (const [label, extract] of FORBIDDEN) {
            const needle = extract(bodies);
            if (!needle) continue;
            expect(dump, `localStorage must not contain ${label}`).not.toContain(needle);
        }
        // The unwrapped key never has a serialisable form to leak, but the
        // wrapped one does — check the field name too, in case a future change
        // stores a different blob under it.
        expect(dump).not.toMatch(/privateKeyEnc/);
        expect(dump).not.toMatch(/authSecret/);
        expect(dump).not.toMatch(/\bkek\b/);
    }

    it('after registration', async () => {
        const { enrollNewAccount } = await import('../../public/js/auth-flow.js');
        respond({ message: 'ok' }, 201);
        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });
        assertStorageClean(sentBodies());
    });

    it('after a legacy account upgrade', async () => {
        const { upgradeLegacyAccount } = await import('../../public/js/auth-flow.js');
        respond([]);
        respond({ message: 'Account upgraded.', authVersion: 2, legacyVaultsPending: 0 });

        await upgradeLegacyAccount({
            userId: 1, email: EMAIL, authVersion: 1,
            encryptionSalt: 'ff'.repeat(16), token: 'jwt'
        }, PASSWORD);

        assertStorageClean(sentBodies());
    });

    it('after a password rotation', { timeout: 30_000 }, async () => {
        const { enrollNewAccount, rotateMasterPassword } = await import('../../public/js/auth-flow.js');
        respond({ message: 'ok' }, 201);
        await enrollNewAccount({ email: EMAIL, password: PASSWORD, turnstileToken: 'tok' });
        const { privateKeyEnc, kdfSalt } = bodyOf('/register');

        respond({ authVersion: 2, kdfSalt, kdfParams: { m: 47104, t: 1, p: 1, len: 32 } });
        respond({ message: 'ok' });
        await rotateMasterPassword({
            email: EMAIL, userId: 1,
            oldPassword: PASSWORD, newPassword: 'a whole new passphrase!1',
            privateKeyEnc
        });

        assertStorageClean(sentBodies());
    });

    it('keeps the re-sealed key in memory, where a password change can still find it', async () => {
        // The reason persisting it felt necessary. It isn't: state.js holds it
        // for the life of the session, which is exactly as long as it is usable.
        const { setWrappedPrivateKey, getWrappedPrivateKey, reset } = await import('../../public/js/state.js');
        reset();
        expect(getWrappedPrivateKey()).toBeNull();
        setWrappedPrivateKey('iv:ct');
        expect(getWrappedPrivateKey()).toBe('iv:ct');
        expect(JSON.stringify(localStorage)).not.toContain('iv:ct');
        reset();
        expect(getWrappedPrivateKey()).toBeNull();
    });
});
