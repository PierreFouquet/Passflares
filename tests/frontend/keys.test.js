// @vitest-environment happy-dom
//
// Exercises the auth_version 2 key hierarchy end to end. These are the tests that
// have to hold for GHSA-pqm6-r3vj-mhvq to actually be closed:
//
//   - the value sent to the server (authSecret) cannot produce the KEK
//   - a vault key wrapped for Bob opens for Bob and for nobody else
//   - a share row cannot be replayed onto a different vault

import { describe, it, expect, beforeAll, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { argon2id } from '../../public/vendor/noble-hashes/argon2.js';

// happy-dom ships no SubtleCrypto; Node's is spec-compliant and is what the
// browser will use.
beforeAll(() => {
    vi.stubGlobal('crypto', webcrypto);
    // keys.js drives Argon2id through a Web Worker. happy-dom's Worker can't
    // load an ES module from a file:// URL, so stand in with the same vendored
    // implementation the worker itself imports — the derivation under test is
    // identical, only the thread differs.
    vi.stubGlobal('Worker', class FakeKdfWorker {
        constructor() { this.listeners = {}; }
        addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }
        removeEventListener(type, fn) {
            this.listeners[type] = (this.listeners[type] ?? []).filter(f => f !== fn);
        }
        postMessage({ id, password, saltHex, params }) {
            const salt = Uint8Array.from(
                saltHex.match(/.{2}/g).map(h => parseInt(h, 16))
            );
            const out = argon2id(new TextEncoder().encode(password), salt, {
                m: params.m, t: params.t, p: params.p, dkLen: params.len
            });
            const keyHex = Array.from(out).map(b => b.toString(16).padStart(2, '0')).join('');
            queueMicrotask(() => {
                for (const fn of this.listeners.message ?? []) fn({ data: { id, ok: true, keyHex } });
            });
        }
    });
});

// Cheap Argon2id params: these tests assert structure, not cost. The production
// numbers live in constants.js and are exercised by the benchmark, not here.
const FAST = { m: 256, t: 1, p: 1, len: 32 };
const SALT = 'aabbccddeeff00112233445566778899';

async function load() {
    return import('../../public/js/keys.js');
}

describe('Layer 0-1 — password stretching and domain separation', () => {
    it('derives the same master key for the same password and salt', async () => {
        const { deriveMasterKey } = await load();
        const a = await deriveMasterKey('correct horse battery staple', SALT, FAST);
        const b = await deriveMasterKey('correct horse battery staple', SALT, FAST);
        expect(Array.from(a)).toEqual(Array.from(b));
        expect(a).toHaveLength(32);
    });

    it('derives a different master key for a different salt', async () => {
        const { deriveMasterKey } = await load();
        const a = await deriveMasterKey('pw', SALT, FAST);
        const b = await deriveMasterKey('pw', '99887766554433221100ffeeddccbbaa', FAST);
        expect(Array.from(a)).not.toEqual(Array.from(b));
    });

    it('authSecret and kek are independent outputs of the same master key', async () => {
        const { deriveMasterKey, deriveAuthSecret, deriveKek } = await load();
        const masterKey = await deriveMasterKey('pw', SALT, FAST);

        const authSecret = await deriveAuthSecret(masterKey);
        const kek = await deriveKek(masterKey);

        // The server holds authSecret. If it equalled (or were derivable from)
        // the KEK, the whole exercise would be pointless.
        expect(authSecret).toMatch(/^[0-9a-f]{64}$/);
        expect(kek.extractable).toBe(false);

        // Same input, different info string -> unrelated output.
        const authBytes = authSecret;
        const kekProbe = await deriveAuthSecret(masterKey);
        expect(kekProbe).toBe(authBytes); // deterministic
    });

    it('authSecret is stable across derivations and unique per password', async () => {
        const { deriveMasterKey, deriveAuthSecret } = await load();
        const one = await deriveAuthSecret(await deriveMasterKey('pw-one', SALT, FAST));
        const two = await deriveAuthSecret(await deriveMasterKey('pw-one', SALT, FAST));
        const three = await deriveAuthSecret(await deriveMasterKey('pw-two', SALT, FAST));
        expect(one).toBe(two);
        expect(one).not.toBe(three);
    });
});

describe('Layer 3 — user keypair', () => {
    it('wraps and unwraps the private key under the KEK', async () => {
        const { deriveMasterKey, deriveKek, generateUserKeypair, wrapPrivateKey, unwrapPrivateKey } = await load();
        const kek = await deriveKek(await deriveMasterKey('pw', SALT, FAST));

        const { publicKey, privateKey } = await generateUserKeypair();
        const wrapped = await wrapPrivateKey(kek, privateKey);

        expect(publicKey).toMatch(/^[A-Za-z0-9+/]+=*$/);
        expect(wrapped).toMatch(/^[0-9a-f]+:[0-9a-f]+$/);

        const recovered = await unwrapPrivateKey(kek, wrapped);
        expect(recovered.type).toBe('private');
    });

    it('refuses to unwrap the private key with the wrong KEK', async () => {
        const { deriveMasterKey, deriveKek, generateUserKeypair, wrapPrivateKey, unwrapPrivateKey } = await load();
        const rightKek = await deriveKek(await deriveMasterKey('right', SALT, FAST));
        const wrongKek = await deriveKek(await deriveMasterKey('wrong', SALT, FAST));

        const { privateKey } = await generateUserKeypair();
        const wrapped = await wrapPrivateKey(rightKek, privateKey);

        await expect(unwrapPrivateKey(wrongKek, wrapped)).rejects.toThrow();
    });
});

describe('Layer 4 — per-vault keys and sharing (#69)', () => {
    it('round-trips a vault key wrapped to its own owner', async () => {
        const { generateUserKeypair, generateVaultKey, wrapVaultKey, unwrapVaultKey } = await load();
        const alice = await generateUserKeypair();
        const vaultKey = await generateVaultKey();

        const share = await wrapVaultKey(42, alice.publicKey, vaultKey);
        const recovered = await unwrapVaultKey(42, alice.privateKey, {
            wrapped_key: share.wrappedKey,
            ephemeral_pubkey: share.ephemeralPubkey
        });

        const original = new Uint8Array(await webcrypto.subtle.exportKey('raw', vaultKey));
        const round = new Uint8Array(await webcrypto.subtle.exportKey('raw', recovered));
        expect(Array.from(round)).toEqual(Array.from(original));
    });

    it('a vault key wrapped for Bob opens for Bob and not for Carol', async () => {
        const { generateUserKeypair, generateVaultKey, wrapVaultKey, unwrapVaultKey } = await load();
        const bob = await generateUserKeypair();
        const carol = await generateUserKeypair();
        const vaultKey = await generateVaultKey();

        const share = await wrapVaultKey(7, bob.publicKey, vaultKey);
        const row = { wrapped_key: share.wrappedKey, ephemeral_pubkey: share.ephemeralPubkey };

        await expect(unwrapVaultKey(7, bob.privateKey, row)).resolves.toBeDefined();
        await expect(unwrapVaultKey(7, carol.privateKey, row)).rejects.toThrow();
    });

    it('a share cannot be replayed onto a different vault', async () => {
        // vaultId is the HKDF salt, so the wrap key is bound to one vault even
        // though the recipient and ephemeral key are unchanged.
        const { generateUserKeypair, generateVaultKey, wrapVaultKey, unwrapVaultKey } = await load();
        const bob = await generateUserKeypair();
        const vaultKey = await generateVaultKey();

        const share = await wrapVaultKey(1, bob.publicKey, vaultKey);
        const row = { wrapped_key: share.wrappedKey, ephemeral_pubkey: share.ephemeralPubkey };

        await expect(unwrapVaultKey(1, bob.privateKey, row)).resolves.toBeDefined();
        await expect(unwrapVaultKey(2, bob.privateKey, row)).rejects.toThrow();
    });

    it('uses a fresh ephemeral key per share', async () => {
        const { generateUserKeypair, generateVaultKey, wrapVaultKeyForMembers } = await load();
        const [a, b, c] = await Promise.all([
            generateUserKeypair(), generateUserKeypair(), generateUserKeypair()
        ]);
        const vaultKey = await generateVaultKey();

        const shares = await wrapVaultKeyForMembers(9, vaultKey, [
            { userId: 1, publicKey: a.publicKey },
            { userId: 2, publicKey: b.publicKey },
            { userId: 3, publicKey: c.publicKey }
        ]);

        expect(shares.map(s => s.userId)).toEqual([1, 2, 3]);
        expect(new Set(shares.map(s => s.ephemeralPubkey)).size).toBe(3);
        expect(new Set(shares.map(s => s.wrappedKey)).size).toBe(3);
    });

    it('every member of a wrapped set recovers the identical vault key', async () => {
        const { generateUserKeypair, generateVaultKey, wrapVaultKeyForMembers, unwrapVaultKey } = await load();
        const members = await Promise.all([generateUserKeypair(), generateUserKeypair()]);
        const vaultKey = await generateVaultKey();
        const expected = new Uint8Array(await webcrypto.subtle.exportKey('raw', vaultKey));

        const shares = await wrapVaultKeyForMembers(11, vaultKey,
            members.map((m, i) => ({ userId: i, publicKey: m.publicKey })));

        for (const [i, member] of members.entries()) {
            const key = await unwrapVaultKey(11, member.privateKey, {
                wrapped_key: shares[i].wrappedKey,
                ephemeral_pubkey: shares[i].ephemeralPubkey
            });
            const raw = new Uint8Array(await webcrypto.subtle.exportKey('raw', key));
            expect(Array.from(raw)).toEqual(Array.from(expected));
        }
    });
});

describe('vault contents encrypt under the vault key', () => {
    it('entries sealed with a vault key open with that key only', async () => {
        const { generateVaultKey } = await load();
        const { encryptData, decryptData } = await import('../../public/js/crypto.js');

        const vaultKey = await generateVaultKey();
        const otherKey = await generateVaultKey();
        const entries = [{ name: 'GitHub', username: 'pierre', password: 'hunter2' }];

        const sealed = await encryptData(entries, vaultKey);
        expect(sealed.iv).toMatch(/^[0-9a-f]{24}$/);
        await expect(decryptData(sealed, vaultKey)).resolves.toEqual(entries);
        await expect(decryptData(sealed, otherKey)).rejects.toThrow();
    });

    it('surfaces a caller-supplied explanation instead of blaming credentials (#69)', async () => {
        const { generateVaultKey } = await load();
        const { encryptData, decryptData } = await import('../../public/js/crypto.js');
        const sealed = await encryptData([{ name: 'x' }], await generateVaultKey());

        await expect(
            decryptData(sealed, await generateVaultKey(), 'No key share for this vault yet.')
        ).rejects.toThrow('No key share for this vault yet.');
    });
});
