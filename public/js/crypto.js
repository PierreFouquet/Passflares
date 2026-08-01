// public/js/crypto.js — symmetric encryption of vault contents.
//
// Vault entries are sealed with AES-256-GCM under a *vault key* (see keys.js),
// not under anything derived directly from the master password. This file only
// knows how to seal and open a payload given a CryptoKey; where that key comes
// from, and who is allowed to hold it, is keys.js's problem.
//
// The one exception is deriveLegacyKey below, which reproduces the auth_version 1
// scheme (PBKDF2 straight from the master password) purely so that accounts which
// have not yet been upgraded can still be read — and migrated.

import {
    AES_IV_LENGTH,
    ENCRYPTION_ALGORITHM,
    KDF_ITERATIONS,
    AUTH_TAG_LENGTH
} from './constants.js';
import { uint8ArrayToHexString, hexStringToUint8Array } from './utils.js';

/**
 * auth_version 1 vault key: PBKDF2-SHA256 over the master password itself.
 *
 * DEPRECATED — do not use for new data. This is the derivation that made the
 * service server-trusting (GHSA-pqm6-r3vj-mhvq): the server received the
 * password and stored the salt, so it held both PBKDF2 inputs. It survives only
 * to decrypt pre-upgrade ciphertext during migration. New keys come from
 * keys.js (Argon2id -> HKDF -> per-vault keys).
 *
 * @param {string} masterPassword
 * @param {string} saltHex  users.encryption_salt
 * @returns {Promise<CryptoKey>} AES-256-GCM
 */
export async function deriveLegacyKey(masterPassword, saltHex) {
    const passwordBytes = new TextEncoder().encode(masterPassword);
    const saltBytes = hexStringToUint8Array(saltHex);

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordBytes,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltBytes,
            iterations: KDF_ITERATIONS,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: ENCRYPTION_ALGORITHM, length: 256 }, // AES-256
        true, // extractable
        ['encrypt', 'decrypt']
    );
}

export async function encryptData(data, encryptionKey) {
    if (!encryptionKey) {
        throw new Error('Encryption key not available — please sign in again to unlock your vaults.');
    }
    const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
    const encodedData = new TextEncoder().encode(JSON.stringify(data));

    const ciphertext = await crypto.subtle.encrypt(
        { name: ENCRYPTION_ALGORITHM, iv: iv, tagLength: AUTH_TAG_LENGTH },
        encryptionKey,
        encodedData
    );

    return {
        iv: uint8ArrayToHexString(iv),
        ciphertext: uint8ArrayToHexString(new Uint8Array(ciphertext))
    };
}

/**
 * @param {{iv: string, ciphertext: string}} encryptedData
 * @param {CryptoKey} encryptionKey  The vault key, not the user's key.
 * @param {string} [context]  Appended to the failure message. Callers that know
 *   *why* decryption could legitimately fail (e.g. a shared vault the user has
 *   no key share for) should pass an explanation — the old blanket "verify your
 *   credentials" told org members their password was wrong when it wasn't (#69).
 */
export async function decryptData(encryptedData, encryptionKey, context = '') {
    if (!encryptionKey) {
        throw new Error('Encryption key not available — please sign in again to unlock your vaults.');
    }
    try {
        const iv = hexStringToUint8Array(encryptedData.iv);
        const ciphertext = hexStringToUint8Array(encryptedData.ciphertext);

        const decrypted = await crypto.subtle.decrypt(
            { name: ENCRYPTION_ALGORITHM, iv: iv, tagLength: AUTH_TAG_LENGTH },
            encryptionKey,
            ciphertext
        );

        return JSON.parse(new TextDecoder().decode(decrypted));
    } catch (error) {
        console.error('Decryption failed');
        throw new Error(context || 'Failed to decrypt this vault. Its contents may have been encrypted with a different key.');
    }
}
