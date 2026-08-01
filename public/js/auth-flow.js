// public/js/auth-flow.js — enrolment, sign-in, and the legacy account upgrade.
//
// Split out of pages/auth.js because none of this is presentation: it is the
// sequence that decides what leaves the browser. Keeping it in one file makes
// the security-relevant question — "what is on the wire?" — answerable by
// reading a single module.
//
// The answer, for auth_version 2:
//   register  { email, authSecret, kdfSalt, kdfParams, publicKey, privateKeyEnc }
//   login     { email, authSecret }
//
// The master password appears in none of them. It is used only as an argument to
// deriveMasterKey() and then goes out of scope.

import {
    getAuthParams, registerUser, loginUser, upgradeAccount, updateMasterPassword,
    getVaults as apiGetVaults, loadEncryptedVaultData, saveEncryptedVaultData
} from './api.js';
import {
    deriveMasterKey, deriveAuthSecret, deriveKek,
    generateUserKeypair, wrapPrivateKey, unwrapPrivateKey, rewrapPrivateKey,
    generateVaultKey, wrapVaultKey
} from './keys.js';
import { deriveLegacyKey, encryptData, decryptData } from './crypto.js';
import { ARGON2_PARAMS } from './constants.js';
import { generateSalt, uint8ArrayToHexString } from './utils.js';
import { setPrivateKey, setWrappedPrivateKey, setVaultKey, setLegacyKey } from './state.js';

export const AUTH_VERSION_LEGACY = 1;
export const AUTH_VERSION_KEY_HIERARCHY = 2;

/**
 * Derives everything the key hierarchy needs from a password.
 * The returned masterKey is zeroed by the caller once authSecret and kek are out.
 */
async function deriveHierarchy(password, kdfSaltHex, params = ARGON2_PARAMS) {
    const masterKey = await deriveMasterKey(password, kdfSaltHex, params);
    const authSecret = await deriveAuthSecret(masterKey);
    const kek = await deriveKek(masterKey);
    masterKey.fill(0);
    return { authSecret, kek };
}

/** Fresh Argon2id salt + the current cost profile, for a new or rotated password. */
export function freshKdfConfig() {
    return { kdfSalt: uint8ArrayToHexString(generateSalt(16)), kdfParams: ARGON2_PARAMS };
}

/**
 * Re-derives this account's auth secret and KEK from the password, using the
 * Argon2id parameters currently on file.
 *
 * Used wherever the server wants proof of the master password — 2FA changes,
 * account deletion, password rotation. It sends the same verifier login does,
 * never the password.
 */
export async function deriveExistingHierarchy(email, password) {
    const params = await getAuthParams(email);
    if (params.authVersion === AUTH_VERSION_LEGACY) {
        throw new Error('Please sign out and sign back in to finish upgrading your account, then try again.');
    }
    return deriveHierarchy(password, params.kdfSalt, params.kdfParams);
}

/**
 * Rotates the master password.
 *
 * Under the key hierarchy this touches exactly three stored values — the
 * Argon2id salt, the auth verifier, and the private key re-sealed under the new
 * KEK. Vault ciphertext is not read, rewritten, or even fetched, which is what
 * removes the partial-corruption window described in #70: there is no longer an
 * interval in which R2 and D1 disagree about which key is live.
 *
 * @returns {Promise<{kdfSalt: string, kdfParams: object, privateKeyEnc: string}>}
 */
export async function rotateMasterPassword({ email, userId, oldPassword, newPassword, privateKeyEnc }) {
    if (!privateKeyEnc) {
        throw new Error('Your encryption keys are not loaded. Please sign out and back in, then try again.');
    }

    const params = await getAuthParams(email);
    if (params.authVersion === AUTH_VERSION_LEGACY) {
        throw new Error('Please sign out and sign back in to finish upgrading your account, then try again.');
    }

    const { authSecret: oldAuthSecret, kek: oldKek } =
        await deriveHierarchy(oldPassword, params.kdfSalt, params.kdfParams);

    const { kdfSalt, kdfParams } = freshKdfConfig();
    const { authSecret: newAuthSecret, kek: newKek } =
        await deriveHierarchy(newPassword, kdfSalt, kdfParams);

    // Fails here if the old password was wrong — before anything is sent, and
    // long before anything is stored.
    const newPrivateKeyEnc = await rewrapPrivateKey(oldKek, newKek, privateKeyEnc)
        .catch(() => { throw new Error('Current master password is incorrect.'); });

    await updateMasterPassword(userId, {
        oldAuthSecret,
        newAuthSecret,
        newKdfSalt: kdfSalt,
        newKdfParams: kdfParams,
        newPrivateKeyEnc
    });

    setWrappedPrivateKey(newPrivateKeyEnc);
    return { kdfSalt, kdfParams, privateKeyEnc: newPrivateKeyEnc };
}

/**
 * Creates an auth_version 2 account. The server receives an auth verifier and a
 * public key; the private key arrives already sealed under a KEK it cannot derive.
 */
export async function enrollNewAccount({ email, password, turnstileToken }) {
    const { kdfSalt, kdfParams } = freshKdfConfig();
    const { authSecret, kek } = await deriveHierarchy(password, kdfSalt, kdfParams);

    const { publicKey, privateKey } = await generateUserKeypair();
    const privateKeyEnc = await wrapPrivateKey(kek, privateKey);

    await registerUser({ email, authSecret, kdfSalt, kdfParams, publicKey, privateKeyEnc, turnstileToken });
}

/**
 * Signs in, running whichever flow the account needs.
 *
 * Returns the server response plus the KEK, which the caller needs to finish
 * establishing the session (and which must never be persisted).
 */
export async function signIn({ email, password, turnstileToken }) {
    const params = await getAuthParams(email);

    if (params.authVersion === AUTH_VERSION_LEGACY) {
        // The one remaining path where a password crosses the wire, and only
        // until this account finishes upgrading a moment from now.
        const response = await loginUser(email, { masterPassword: password }, turnstileToken);
        return { response, kek: null, authVersion: AUTH_VERSION_LEGACY };
    }

    const { authSecret, kek } = await deriveHierarchy(password, params.kdfSalt, params.kdfParams);
    const response = await loginUser(email, { authSecret }, turnstileToken);
    return { response, kek, authVersion: AUTH_VERSION_KEY_HIERARCHY };
}

/**
 * Puts an upgraded account's key material into session state: unwrap the private
 * key with the KEK, and keep the legacy PBKDF2 key around if organisation vaults
 * are still waiting to be rescued (#69).
 */
export async function establishKeySession(response, kek, password) {
    if (!response.privateKeyEnc) {
        throw new Error('Your account is missing its encryption keys. Please contact support before continuing.');
    }
    const privateKey = await unwrapPrivateKey(kek, response.privateKeyEnc).catch(() => {
        // The KEK comes straight from the password, and the server already
        // accepted the auth secret derived from it — so this is a corrupt or
        // mismatched stored blob, not a typo.
        throw new Error('Your stored keys could not be unlocked. They may be corrupt — please contact support.');
    });
    setPrivateKey(privateKey);
    setWrappedPrivateKey(response.privateKeyEnc);

    if (response.legacyVaultsPending > 0 && response.encryptionSalt) {
        setLegacyKey(await deriveLegacyKey(password, response.encryptionSalt));
    }
}

/**
 * The auth_version 1 -> 2 upgrade, run immediately after a legacy sign-in while
 * the password is still in memory.
 *
 * Ordering matters. Every re-encrypted vault is written to a *staged* R2 key
 * (<object>.v2) while the live v1 blob stays put; only the server's single
 * D1 batch — which flips current_key_version alongside the new credentials —
 * makes the new copies authoritative. If anything here throws, the account is
 * untouched on v1 and every original blob is still the one being served.
 *
 * @returns {Promise<{vaultsRekeyed: number, legacyVaultsPending: number}>}
 */
export async function upgradeLegacyAccount(response, password) {
    const legacyKey = await deriveLegacyKey(password, response.encryptionSalt);

    const { kdfSalt, kdfParams } = freshKdfConfig();
    const { authSecret, kek } = await deriveHierarchy(password, kdfSalt, kdfParams);
    const { publicKey, privateKey } = await generateUserKeypair();
    const privateKeyEnc = await wrapPrivateKey(kek, privateKey);

    // Only vaults this user personally owns and can write. Organisation vaults
    // are skipped: re-keying one would make it unreadable to every other member,
    // and a read-only org vault would 403 halfway through the loop — the exact
    // partial-corruption path described in #70.
    const allVaults = await apiGetVaults();
    const ownVaults = allVaults.filter(v => v.owner_type === 'user' && v.permission_level === 'manage');

    const shares = [];
    const newVaultKeys = new Map();
    const failed = [];

    for (const vault of ownVaults) {
        try {
            const raw = await loadEncryptedVaultData(vault.id);
            const entries = raw?.encryptedData
                ? await decryptData(raw.encryptedData, legacyKey, `Could not decrypt "${vault.name}".`)
                : [];

            const vaultKey = await generateVaultKey();
            const reEncrypted = await encryptData(entries, vaultKey);

            // Staged, not live — see the note above.
            await saveEncryptedVaultData(vault.id, reEncrypted, 'v2');

            const wrapped = await wrapVaultKey(vault.id, publicKey, vaultKey);
            shares.push({
                vaultId: vault.id,
                wrappedKey: wrapped.wrappedKey,
                ephemeralPubkey: wrapped.ephemeralPubkey
            });
            newVaultKeys.set(vault.id, vaultKey);
        } catch (err) {
            failed.push({ id: vault.id, name: vault.name, reason: err.message });
        }
    }

    if (failed.length > 0) {
        // Abort before committing anything. The staged .v2 objects are orphaned
        // but inert — nothing reads them until current_key_version says so.
        const names = failed.map(f => `"${f.name}"`).join(', ');
        throw new Error(
            `Could not upgrade your account: ${names} could not be re-encrypted. ` +
            `Your data is unchanged and you can keep signing in as before.`
        );
    }

    const result = await upgradeAccount({
        authSecret, kdfSalt, kdfParams, publicKey, privateKeyEnc, vaults: shares
    });

    setPrivateKey(privateKey);
    setWrappedPrivateKey(privateKeyEnc);
    for (const [vaultId, key] of newVaultKeys) setVaultKey(vaultId, key);
    // Retained so pre-upgrade organisation vaults can still be rescued (#69).
    if (result.legacyVaultsPending > 0) setLegacyKey(legacyKey);

    return {
        publicKey,
        privateKeyEnc,
        vaultsRekeyed: shares.length,
        legacyVaultsPending: result.legacyVaultsPending ?? 0
    };
}
