// @vitest-environment happy-dom
//
// Client-side vault key resolution and the #69 repair paths.
//
// The behaviour that matters here is what happens when a vault *cannot* be
// opened. The old code had one answer for every case — "verify your
// credentials" — which was wrong for the most common one: an org member who is
// authorised but has never been given the key.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { webcrypto } from 'node:crypto';

let mockFetch;

beforeEach(async () => {
    vi.stubGlobal('crypto', webcrypto);
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    localStorage.clear();
    localStorage.setItem('jwtToken', 'test-session-token');
    const { reset } = await import('../../public/js/state.js');
    reset();
});

afterEach(() => {
    vi.unstubAllGlobals();
});

function respond(body, status = 200) {
    mockFetch.mockResolvedValueOnce({ ok: true, status, json: () => Promise.resolve(body) });
}

function calledWith(endpoint, method) {
    return mockFetch.mock.calls.some(([url, config]) =>
        url.includes(endpoint) && (!method || config?.method === method));
}

function bodyOf(endpoint, method) {
    const call = mockFetch.mock.calls.find(([url, config]) =>
        url.includes(endpoint) && (!method || config?.method === method) && config?.body);
    return call ? JSON.parse(call[1].body) : null;
}

const PERSONAL_VAULT = { id: 7, name: 'Personal', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage' };
const ORG_VAULT = { id: 8, name: 'Team', owner_type: 'organization', owner_id: 'org_3', permission_level: 'manage' };

describe('orgIdOf', () => {
    it('extracts the numeric org id', async () => {
        const { orgIdOf } = await import('../../public/js/vault-keys.js');
        expect(orgIdOf(ORG_VAULT)).toBe(3);
        expect(orgIdOf(PERSONAL_VAULT)).toBeNull();
        expect(orgIdOf({ owner_type: 'organization', owner_id: 'org_nope' })).toBeNull();
    });
});

describe('decryptVaultContents', () => {
    it('opens a vault with the key from its share', async () => {
        const { generateUserKeypair, generateVaultKey, wrapVaultKey } = await import('../../public/js/keys.js');
        const { encryptData } = await import('../../public/js/crypto.js');
        const { decryptVaultContents } = await import('../../public/js/vault-keys.js');
        const { setPrivateKey } = await import('../../public/js/state.js');

        const me = await generateUserKeypair();
        setPrivateKey(me.privateKey);

        const vaultKey = await generateVaultKey();
        const entries = [{ name: 'GitHub', password: 'hunter2' }];
        const blob = await encryptData(entries, vaultKey);
        const share = await wrapVaultKey(PERSONAL_VAULT.id, me.publicKey, vaultKey);

        respond({ encryptedData: blob, keyVersion: 'v2' });
        respond({ share: { wrapped_key: share.wrappedKey, ephemeral_pubkey: share.ephemeralPubkey } });

        const result = await decryptVaultContents(PERSONAL_VAULT);
        expect(result.entries).toEqual(entries);
        expect(result.usedLegacyKey).toBe(false);
    });

    it('explains that an org vault is awaiting a key rather than blaming credentials (#69)', async () => {
        // The exact scenario in #69: Bob is a legitimate admin, the backend
        // authorises him correctly, and the old client told him his password was
        // wrong.
        const { decryptVaultContents, VaultKeyUnavailableError } = await import('../../public/js/vault-keys.js');
        const { setPrivateKey } = await import('../../public/js/state.js');
        const { generateUserKeypair } = await import('../../public/js/keys.js');

        setPrivateKey((await generateUserKeypair()).privateKey);

        respond({ encryptedData: { iv: 'aa'.repeat(12), ciphertext: 'bb'.repeat(40) } });
        respond({ share: null, reason: 'no_key_share' });

        const error = await decryptVaultContents(ORG_VAULT).catch(e => e);
        expect(error).toBeInstanceOf(VaultKeyUnavailableError);
        expect(error.reason).toBe('no_key_share');
        expect(error.message).toMatch(/administrator/i);
        expect(error.message).not.toMatch(/credential|password/i);
    });

    it('falls back to the legacy key for a vault that predates the hierarchy', async () => {
        const { deriveLegacyKey, encryptData } = await import('../../public/js/crypto.js');
        const { decryptVaultContents } = await import('../../public/js/vault-keys.js');
        const { setPrivateKey, setLegacyKey } = await import('../../public/js/state.js');
        const { generateUserKeypair } = await import('../../public/js/keys.js');

        setPrivateKey((await generateUserKeypair()).privateKey);
        const legacyKey = await deriveLegacyKey('pw', 'ff'.repeat(16));
        setLegacyKey(legacyKey);

        const entries = [{ name: 'Old entry' }];
        respond({ encryptedData: await encryptData(entries, legacyKey), keyVersion: 'v1' });
        respond({ share: null, reason: 'no_key_share' });

        const result = await decryptVaultContents(ORG_VAULT);
        expect(result.entries).toEqual(entries);
        // The signal that triggers the rescue.
        expect(result.usedLegacyKey).toBe(true);
    });

    it('treats an empty vault as readable, not broken', async () => {
        const { decryptVaultContents } = await import('../../public/js/vault-keys.js');
        const { setPrivateKey } = await import('../../public/js/state.js');
        const { generateUserKeypair } = await import('../../public/js/keys.js');

        setPrivateKey((await generateUserKeypair()).privateKey);
        respond(null);
        respond({ share: null });

        const result = await decryptVaultContents(PERSONAL_VAULT);
        expect(result.entries).toEqual([]);
    });

    it('reports a lost session distinctly from a missing key', async () => {
        const { decryptVaultContents } = await import('../../public/js/vault-keys.js');
        respond({ encryptedData: { iv: 'aa', ciphertext: 'bb' } });
        await expect(decryptVaultContents(PERSONAL_VAULT)).rejects.toThrow(/sign in again/i);
    });
});

describe('rescueLegacyOrgVault (#69)', () => {
    it('re-keys the vault and wraps the new key for every member with a public key', async () => {
        const { generateUserKeypair, unwrapVaultKey } = await import('../../public/js/keys.js');
        const { rescueLegacyOrgVault } = await import('../../public/js/vault-keys.js');

        const alice = await generateUserKeypair();
        const bob = await generateUserKeypair();

        respond({ message: 'Staged.', staged: true });                  // stage .v2 blob
        respond({ members: [                                            // member keys
            { userId: 1, email: 'alice@x.com', publicKey: alice.publicKey },
            { userId: 2, email: 'bob@x.com', publicKey: bob.publicKey },
            { userId: 3, email: 'carol@x.com', publicKey: null }        // not upgraded
        ] });
        respond({ message: 'Vault key shares updated.', count: 2 });    // put shares
        respond({ message: 'Key versions committed.' });                // commit

        const entries = [{ name: 'Shared secret' }];
        const { vaultKey, granted, skipped } = await rescueLegacyOrgVault(ORG_VAULT, entries);

        expect(granted).toBe(2);
        expect(skipped.map(m => m.email)).toEqual(['carol@x.com']);

        // Bob can now open it — the whole point of #69.
        const shares = bodyOf('/vaults/8/shares', 'PUT').shares;
        const bobShare = shares.find(s => s.userId === 2);
        const recovered = await unwrapVaultKey(ORG_VAULT.id, bob.privateKey, {
            wrapped_key: bobShare.wrappedKey,
            ephemeral_pubkey: bobShare.ephemeralPubkey
        });
        const expected = new Uint8Array(await webcrypto.subtle.exportKey('raw', vaultKey));
        const actual = new Uint8Array(await webcrypto.subtle.exportKey('raw', recovered));
        expect(Array.from(actual)).toEqual(Array.from(expected));
    });

    it('stages the new blob before committing, so a failure cannot destroy the old one', async () => {
        const { generateUserKeypair } = await import('../../public/js/keys.js');
        const { rescueLegacyOrgVault } = await import('../../public/js/vault-keys.js');
        const alice = await generateUserKeypair();

        respond({ staged: true });
        respond({ members: [{ userId: 1, email: 'a@x.com', publicKey: alice.publicKey }] });
        respond({ count: 1 });
        respond({ message: 'committed' });

        await rescueLegacyOrgVault(ORG_VAULT, [{ name: 'x' }]);

        expect(bodyOf('/vaults/8/data', 'PUT').keyVersion).toBe('v2');
        // Shares replace wholesale — a stale row would still unwrap the old key.
        expect(bodyOf('/vaults/8/shares', 'PUT').replace).toBe(true);
        // The commit is last: until it lands, reads still serve the v1 blob.
        const order = mockFetch.mock.calls.map(([url]) => url);
        expect(order.indexOf('/api/vaults/key-version/commit')).toBe(order.length - 1);
    });
});

describe('provisionVaultKey', () => {
    it('wraps a new personal vault key for its creator only', async () => {
        const { generateUserKeypair } = await import('../../public/js/keys.js');
        const { provisionVaultKey } = await import('../../public/js/vault-keys.js');
        const me = await generateUserKeypair();

        respond({ count: 1 });
        const { granted } = await provisionVaultKey(PERSONAL_VAULT, { selfUserId: 1, selfPublicKey: me.publicKey });

        expect(granted).toBe(1);
        expect(calledWith('/organizations', 'GET')).toBe(false);
        expect(bodyOf('/vaults/7/shares', 'PUT').shares.map(s => s.userId)).toEqual([1]);
    });

    it('wraps a new org vault key for every current member', async () => {
        const { generateUserKeypair } = await import('../../public/js/keys.js');
        const { provisionVaultKey } = await import('../../public/js/vault-keys.js');
        const me = await generateUserKeypair();
        const bob = await generateUserKeypair();

        respond({ members: [
            { userId: 1, email: 'me@x.com', publicKey: me.publicKey },
            { userId: 2, email: 'bob@x.com', publicKey: bob.publicKey },
            { userId: 3, email: 'carol@x.com', publicKey: null }
        ] });
        respond({ count: 2 });

        const { granted, skipped } = await provisionVaultKey(ORG_VAULT, { selfUserId: 1, selfPublicKey: me.publicKey });

        expect(granted).toBe(2);
        expect(skipped).toHaveLength(1);
        expect(bodyOf('/vaults/8/shares', 'PUT').shares.map(s => s.userId).sort()).toEqual([1, 2]);
    });
});

describe('rotateVaultKey', () => {
    it('produces a key the removed member\'s old share can no longer unwrap', async () => {
        // Revocation has to assume the removed member cached the key, so the key
        // itself changes and the contents are re-encrypted under the new one.
        const { generateUserKeypair, generateVaultKey, wrapVaultKey, unwrapVaultKey } =
            await import('../../public/js/keys.js');
        const { rotateVaultKey } = await import('../../public/js/vault-keys.js');

        const alice = await generateUserKeypair();
        const evicted = await generateUserKeypair();

        const oldKey = await generateVaultKey();
        const staleShare = await wrapVaultKey(ORG_VAULT.id, evicted.publicKey, oldKey);

        respond({ staged: true });
        respond({ count: 1 });
        respond({ message: 'committed' });

        const newKey = await rotateVaultKey(ORG_VAULT, [{ name: 'x' }], [
            { userId: 1, publicKey: alice.publicKey }
        ]);

        const stale = await unwrapVaultKey(ORG_VAULT.id, evicted.privateKey, {
            wrapped_key: staleShare.wrappedKey, ephemeral_pubkey: staleShare.ephemeralPubkey
        });
        const staleRaw = new Uint8Array(await webcrypto.subtle.exportKey('raw', stale));
        const newRaw = new Uint8Array(await webcrypto.subtle.exportKey('raw', newKey));
        expect(Array.from(staleRaw)).not.toEqual(Array.from(newRaw));

        expect(bodyOf('/vaults/8/shares', 'PUT').replace).toBe(true);
    });
});

describe('grantVaultKeyTo', () => {
    it('refuses to wrap for a member who has not set up their keys yet', async () => {
        const { grantVaultKeyTo, VaultKeyUnavailableError } = await import('../../public/js/vault-keys.js');
        const { generateVaultKey } = await import('../../public/js/keys.js');

        await expect(
            grantVaultKeyTo(8, await generateVaultKey(), { userId: 3, email: 'carol@x.com', publicKey: null })
        ).rejects.toThrow(VaultKeyUnavailableError);
        expect(mockFetch).not.toHaveBeenCalled();
    });

    it('writes a single additive share without disturbing the others', async () => {
        const { grantVaultKeyTo } = await import('../../public/js/vault-keys.js');
        const { generateVaultKey, generateUserKeypair } = await import('../../public/js/keys.js');
        const bob = await generateUserKeypair();

        respond({ count: 1 });
        await grantVaultKeyTo(8, await generateVaultKey(), { userId: 2, email: 'b@x.com', publicKey: bob.publicKey });

        const body = bodyOf('/vaults/8/shares', 'PUT');
        expect(body.shares).toHaveLength(1);
        expect(body.replace).toBe(false);
    });
});
