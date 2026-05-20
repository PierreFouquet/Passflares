// public/js/crypto.js

import {
    AES_IV_LENGTH,
    ENCRYPTION_ALGORITHM,
    KDF_ITERATIONS,
    KDF_MEMORY,
    KDF_PARALLELISM,
    AUTH_TAG_LENGTH
} from './constants.js';

// Derive an encryption key from the master password using Argon2id (client-side)
// Note: This PBKDF2 fallback is only if WebCrypto's subtle.deriveKey doesn't support Argon2.
// Browsers typically support PBKDF2 for deriveKey with 'HKDF' or 'PBKDF2' algorithm.
// For Argon2id, we'll use a separate library like argon2-browser if needed, or rely on server-side hashing
// for authentication and use PBKDF2 for client-side encryption key derivation.
// For this project, we are using PBKDF2 for client-side encryption key derivation
// and Argon2id for server-side master password hashing.



export async function deriveKey(masterPassword, saltHex) {
    const passwordBytes = new TextEncoder().encode(masterPassword);
    const saltBytes = hexStringToUint8Array(saltHex);

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passwordBytes,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
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

    return derivedKey;
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

export async function decryptData(encryptedData, encryptionKey) {
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
        throw new Error('Failed to decrypt data. Please verify your credentials.');
    }
}


// --- Helper functions (can be moved to utils.js if shared) ---
function uint8ArrayToHexString(uint8array) {
    return Array.from(uint8array)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexStringToUint8Array(hexString) {
    if (hexString.length % 2 !== 0) {
        throw new Error("Hex string must have an even number of characters.");
    }
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}