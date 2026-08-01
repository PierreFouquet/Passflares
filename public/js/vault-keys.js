// public/js/vault-keys.js — obtaining, granting and rotating per-vault keys.
//
// Every vault has its own random AES-256-GCM key. A member gets a copy by way of
// a vault_key_shares row: that key wrapped to their public key. Holding the row
// is what makes a vault readable — separately from being *authorised* to read it,
// which the server enforces on its own.
//
// Those two can legitimately disagree. An org admin added after a vault was
// created is authorised immediately but holds no key until someone who does
// wraps it for them. Issue #69 is the old code conflating the two and telling
// such a member their password was wrong.

import {
    getVaultKeyShare, putVaultKeyShares, getOrgMemberKeys,
    loadEncryptedVaultData, saveEncryptedVaultData, commitKeyVersions
} from './api.js';
import {
    unwrapVaultKey, generateVaultKey, wrapVaultKey, wrapVaultKeyForMembers
} from './keys.js';
import { encryptData, decryptData } from './crypto.js';
import {
    getPrivateKey, getVaultKey, setVaultKey, getLegacyKey, forgetVaultKey
} from './state.js';

/** 'org_12' -> 12; null for personally-owned vaults. */
export function orgIdOf(vault) {
    if (vault.owner_type !== 'organization') return null;
    const id = Number(String(vault.owner_id).split('_')[1]);
    return Number.isInteger(id) ? id : null;
}

export class VaultKeyUnavailableError extends Error {
    constructor(message, reason) {
        super(message);
        this.name = 'VaultKeyUnavailableError';
        this.reason = reason;
    }
}

/**
 * This user's copy of the vault key, or null if no share has been granted.
 * Cached for the session — unwrapping is an ECDH plus an AES-GCM open.
 */
export async function loadVaultKey(vault) {
    const cached = getVaultKey(vault.id);
    if (cached) return cached;

    const privateKey = getPrivateKey();
    if (!privateKey) {
        throw new VaultKeyUnavailableError(
            'Your session keys are no longer loaded — please sign in again.', 'no_session'
        );
    }

    const { share } = await getVaultKeyShare(vault.id);
    if (!share) return null;

    const key = await unwrapVaultKey(vault.id, privateKey, share);
    setVaultKey(vault.id, key);
    return key;
}

/**
 * Decrypts a vault's contents, trying each key that could legitimately open it.
 *
 * The candidates exist because a vault can be caught mid-migration: its key
 * share may already be written while the blob it points at is still staged (the
 * server flips current_key_version last, deliberately — see #70). Rather than
 * reason about which of those states we're in, try the share key, then the
 * legacy key, and report which one worked so the caller can finish the job.
 *
 * @returns {Promise<{entries: Array, usedLegacyKey: boolean, vaultKey: CryptoKey|null}>}
 */
export async function decryptVaultContents(vault) {
    const raw = await loadEncryptedVaultData(vault.id);
    const vaultKey = await loadVaultKey(vault);

    if (!raw?.encryptedData) {
        // Empty vault. Still needs a key for the first save.
        return { entries: [], usedLegacyKey: false, vaultKey };
    }

    if (vaultKey) {
        try {
            return {
                entries: await decryptData(raw.encryptedData, vaultKey),
                usedLegacyKey: false,
                vaultKey
            };
        } catch {
            // Fall through — a stale share, or a rescue that didn't commit.
        }
    }

    const legacyKey = getLegacyKey();
    if (legacyKey) {
        try {
            return {
                entries: await decryptData(raw.encryptedData, legacyKey),
                usedLegacyKey: true,
                vaultKey
            };
        } catch {
            // Not ours either.
        }
    }

    if (!vaultKey) {
        const shareable = vault.owner_type === 'organization'
            ? 'An administrator who can already open this vault needs to share its key with you.'
            : 'This vault was encrypted with a key this account does not hold.';
        throw new VaultKeyUnavailableError(
            `"${vault.name}" cannot be opened yet. ${shareable}`, 'no_key_share'
        );
    }

    forgetVaultKey(vault.id);
    throw new VaultKeyUnavailableError(
        `"${vault.name}" could not be decrypted with the key you hold. Its key may have been rotated — try reloading.`,
        'stale_key'
    );
}

/**
 * Re-keys an organisation vault that still holds pre-upgrade ciphertext, and
 * wraps the new key for every member who can receive one.
 *
 * This is the #69 repair. Only the member who created the vault can run it —
 * they are the only one whose legacy key ever decrypted it — so it happens
 * lazily, the next time they open it.
 *
 * Non-destructive by construction: the new blob is staged under .v2 and the old
 * one keeps serving reads until commitKeyVersions() succeeds.
 *
 * @returns {Promise<{vaultKey: CryptoKey, granted: number, skipped: Array}>}
 */
export async function rescueLegacyOrgVault(vault, entries) {
    const orgId = orgIdOf(vault);
    if (orgId === null) throw new Error('Not an organisation vault.');

    const vaultKey = await generateVaultKey();
    const reEncrypted = await encryptData(entries, vaultKey);
    await saveEncryptedVaultData(vault.id, reEncrypted, 'v2');

    const { members } = await getOrgMemberKeys(orgId);
    const withKeys = members.filter(m => m.publicKey);
    const skipped = members.filter(m => !m.publicKey);

    const shares = await wrapVaultKeyForMembers(
        vault.id, vaultKey,
        withKeys.map(m => ({ userId: m.userId, publicKey: m.publicKey }))
    );
    await putVaultKeyShares(vault.id, shares, { replace: true, keyVersion: 'v2' });

    // Last: makes the staged blob authoritative.
    await commitKeyVersions([{ vaultId: vault.id, keyVersion: 'v2' }]);

    setVaultKey(vault.id, vaultKey);
    return { vaultKey, granted: shares.length, skipped };
}

/**
 * Generates a key for a freshly created vault and wraps it for everyone who
 * should hold it: the creator alone for a personal vault, every current member
 * for an organisation one.
 *
 * Called *after* the vault row exists, because the wrap is bound to the vault id
 * (which prevents a share being replayed onto a different vault) and that id is
 * assigned by the insert.
 *
 * @returns {Promise<{vaultKey: CryptoKey, granted: number, skipped: Array}>}
 */
export async function provisionVaultKey(vault, { selfUserId, selfPublicKey }) {
    const vaultKey = await generateVaultKey();

    const recipients = [{ userId: selfUserId, publicKey: selfPublicKey }];
    let skipped = [];

    const orgId = orgIdOf(vault);
    if (orgId !== null) {
        const { members } = await getOrgMemberKeys(orgId);
        for (const member of members) {
            if (member.userId === selfUserId) continue;
            // A member who hasn't signed in since the upgrade has no public key
            // yet, so nothing can be wrapped for them. Report rather than drop.
            if (member.publicKey) recipients.push({ userId: member.userId, publicKey: member.publicKey });
            else skipped.push(member);
        }
    }

    const shares = await wrapVaultKeyForMembers(vault.id, vaultKey, recipients);
    await putVaultKeyShares(vault.id, shares, { replace: true, keyVersion: 'v2' });

    setVaultKey(vault.id, vaultKey);
    return { vaultKey, granted: shares.length, skipped };
}

/**
 * Rotates a vault key and re-wraps it for the members who remain.
 *
 * Required after removing someone: deleting their share stops them fetching the
 * key again, but they may already have cached it, so the key itself has to
 * change and the contents must be re-encrypted under the new one.
 */
export async function rotateVaultKey(vault, entries, remainingMembers) {
    const vaultKey = await generateVaultKey();
    const reEncrypted = await encryptData(entries, vaultKey);
    await saveEncryptedVaultData(vault.id, reEncrypted, 'v2');

    const shares = await wrapVaultKeyForMembers(
        vault.id, vaultKey,
        remainingMembers.map(m => ({ userId: m.userId, publicKey: m.publicKey }))
    );
    await putVaultKeyShares(vault.id, shares, { replace: true, keyVersion: 'v2' });
    await commitKeyVersions([{ vaultId: vault.id, keyVersion: 'v2' }]);

    setVaultKey(vault.id, vaultKey);
    return vaultKey;
}

/** Wraps an existing vault key for one newly-added member. */
export async function grantVaultKeyTo(vaultId, vaultKey, member) {
    if (!member.publicKey) {
        throw new VaultKeyUnavailableError(
            `${member.email} has not finished setting up their encryption keys yet. Ask them to sign in once, then share again.`,
            'recipient_not_upgraded'
        );
    }
    const wrapped = await wrapVaultKey(vaultId, member.publicKey, vaultKey);
    await putVaultKeyShares(vaultId, [{
        userId: member.userId,
        wrappedKey: wrapped.wrappedKey,
        ephemeralPubkey: wrapped.ephemeralPubkey
    }], { keyVersion: 'v2' });
}
