// public/js/keys.js — the auth_version 2 key hierarchy.
//
// Everything in this file exists to keep two properties true:
//
//   1. The server never receives a value from which a vault key can be derived.
//   2. A vault key can be handed to another member without either party being
//      online, and without re-encrypting the vault.
//
// The shape:
//
//   masterKey  = Argon2id(password, kdfSalt, params)        browser only
//   authSecret = HKDF(masterKey, "passflares:auth:v2")      -> server (hex)
//   kek        = HKDF(masterKey, "passflares:kek:v2")       browser only
//
//   userKeypair          = P-256 ECDH; private wrapped under kek
//   vaultKey             = random AES-256-GCM key, one per vault
//   vault_key_shares row = vaultKey wrapped to a member's public key (ECIES)
//
// masterKey is a bare secret and is never used as a key directly — authSecret
// and kek are independent HKDF outputs, so a server holding authSecret learns
// nothing about kek.
//
// Why P-256 rather than the X25519 named in issue #71: `crypto.subtle` only
// gained X25519 in Chrome 133 / Firefox 132 / Safari 17, so older browsers would
// hard-fail at login. P-256 ECDH has been universally supported for a decade and
// is hardware-accelerated. The ECIES construction is identical either way, and
// this avoids vendoring a second crypto library into public/.

import {
    ARGON2_PARAMS,
    ENCRYPTION_ALGORITHM,
    AES_IV_LENGTH,
    AUTH_TAG_LENGTH,
    HKDF_INFO_AUTH,
    HKDF_INFO_KEK,
    HKDF_INFO_VAULT_SHARE
} from './constants.js';
import { uint8ArrayToHexString, hexStringToUint8Array } from './utils.js';

const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
const TEXT = new TextEncoder();

// ── base64 for SPKI/PKCS#8 blobs ─────────────────────────────────────────────
// Public keys travel as base64 rather than hex: they're ~91 bytes and end up in
// D1 rows and JSON payloads, where the 2x hex overhead isn't worth it.

export function bytesToBase64(bytes) {
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
}

export function base64ToBytes(b64) {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

// ── Layer 0: password stretching ─────────────────────────────────────────────

let kdfWorker = null;
let kdfSeq = 0;

function getKdfWorker() {
    // One long-lived worker: spinning one up per derivation would re-parse and
    // re-JIT ~80 KB of Argon2 on every login and password change.
    if (!kdfWorker) {
        kdfWorker = new Worker(new URL('./kdf-worker.js', import.meta.url), { type: 'module' });
    }
    return kdfWorker;
}

/**
 * Argon2id(password, kdfSalt) -> 32 raw bytes. Runs in a Web Worker so the ~1s
 * derivation doesn't freeze the UI.
 *
 * @param {string} password  The master password. Never leaves the browser.
 * @param {string} kdfSaltHex  Per-user salt from /api/auth/params.
 * @param {{m:number,t:number,p:number,len:number}} [params]  Per-user Argon2id cost.
 * @returns {Promise<Uint8Array>} masterKey
 */
export function deriveMasterKey(password, kdfSaltHex, params = ARGON2_PARAMS) {
    return new Promise((resolve, reject) => {
        const worker = getKdfWorker();
        const id = ++kdfSeq;

        const onMessage = (event) => {
            if (event.data?.id !== id) return;
            worker.removeEventListener('message', onMessage);
            worker.removeEventListener('error', onError);
            if (event.data.ok) resolve(hexStringToUint8Array(event.data.keyHex));
            else reject(new Error(event.data.error ?? 'Key derivation failed.'));
        };
        const onError = () => {
            worker.removeEventListener('message', onMessage);
            worker.removeEventListener('error', onError);
            reject(new Error('Key derivation worker failed to start.'));
        };

        worker.addEventListener('message', onMessage);
        worker.addEventListener('error', onError);
        worker.postMessage({ id, password, saltHex: kdfSaltHex, params });
    });
}

// ── Layer 1: domain separation ───────────────────────────────────────────────

async function hkdf(masterKey, info, salt = new Uint8Array(0)) {
    const base = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: TEXT.encode(info) },
        base,
        256
    );
    return new Uint8Array(bits);
}

/**
 * The only value derived from the master password that is ever sent to the
 * server. The server applies scrypt to it before storage, so a D1 leak does not
 * hand over authSecret directly — and even authSecret itself cannot produce the
 * KEK, because HKDF is one-way and the two use different `info` strings.
 *
 * @returns {Promise<string>} hex
 */
export async function deriveAuthSecret(masterKey) {
    return uint8ArrayToHexString(await hkdf(masterKey, HKDF_INFO_AUTH));
}

/**
 * Key-encryption key. Wraps the user's private key and nothing else. Never
 * leaves the browser, never touches localStorage.
 *
 * @returns {Promise<CryptoKey>} AES-256-GCM, non-extractable
 */
export async function deriveKek(masterKey) {
    const raw = await hkdf(masterKey, HKDF_INFO_KEK);
    const key = await crypto.subtle.importKey(
        'raw', raw, { name: ENCRYPTION_ALGORITHM }, false, ['encrypt', 'decrypt']
    );
    raw.fill(0);
    return key;
}

// ── AES-GCM blobs, serialised as "ivHex:ctHex" ───────────────────────────────

async function sealRaw(key, plaintextBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));
    const ct = await crypto.subtle.encrypt(
        { name: ENCRYPTION_ALGORITHM, iv, tagLength: AUTH_TAG_LENGTH }, key, plaintextBytes
    );
    return `${uint8ArrayToHexString(iv)}:${uint8ArrayToHexString(new Uint8Array(ct))}`;
}

async function openRaw(key, blob) {
    const [ivHex, ctHex] = String(blob).split(':');
    if (!ivHex || !ctHex) throw new Error('Malformed encrypted blob.');
    const plain = await crypto.subtle.decrypt(
        { name: ENCRYPTION_ALGORITHM, iv: hexStringToUint8Array(ivHex), tagLength: AUTH_TAG_LENGTH },
        key,
        hexStringToUint8Array(ctHex)
    );
    return new Uint8Array(plain);
}

// ── Layer 3: user keypair ────────────────────────────────────────────────────

/**
 * Generates the user's long-term P-256 ECDH identity.
 * The private key is extractable *only* so it can immediately be wrapped under
 * the KEK; the wrapped form is what gets stored.
 *
 * @returns {Promise<{publicKey: string, privateKey: CryptoKey}>} publicKey is base64 SPKI
 */
export async function generateUserKeypair() {
    const pair = await crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveBits']);
    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
    return { publicKey: bytesToBase64(spki), privateKey: pair.privateKey };
}

/** AES-256-GCM(kek, PKCS#8 private key) -> "ivHex:ctHex" for storage in user_keys. */
export async function wrapPrivateKey(kek, privateKey) {
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
    const blob = await sealRaw(kek, pkcs8);
    pkcs8.fill(0);
    return blob;
}

/**
 * Reverses wrapPrivateKey. A failure here means the password was wrong or the
 * stored blob is corrupt — the caller should say so honestly rather than
 * blaming "credentials" generically.
 */
export async function unwrapPrivateKey(kek, wrappedBlob) {
    const pkcs8 = await openRaw(kek, wrappedBlob);
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, ECDH_PARAMS, false, ['deriveBits']);
    pkcs8.fill(0);
    return key;
}

/**
 * Moves the wrapped private key from one KEK to another — the entire cost of a
 * master-password change under the key hierarchy.
 *
 * Works on the raw PKCS#8 bytes rather than importing a CryptoKey, so the
 * private key never has to be marked extractable just to be re-sealed.
 */
export async function rewrapPrivateKey(oldKek, newKek, wrappedBlob) {
    const pkcs8 = await openRaw(oldKek, wrappedBlob);
    const rewrapped = await sealRaw(newKek, pkcs8);
    pkcs8.fill(0);
    return rewrapped;
}

export async function importPublicKey(publicKeyB64) {
    return crypto.subtle.importKey('spki', base64ToBytes(publicKeyB64), ECDH_PARAMS, true, []);
}

// ── Layer 4: per-vault keys ──────────────────────────────────────────────────

/**
 * A fresh random vault key. Extractable so it can be wrapped for members;
 * the wrapped copies are the only form that is ever persisted.
 *
 * @returns {Promise<CryptoKey>} AES-256-GCM
 */
export async function generateVaultKey() {
    return crypto.subtle.generateKey(
        { name: ENCRYPTION_ALGORITHM, length: 256 }, true, ['encrypt', 'decrypt']
    );
}

/**
 * Binds the ECDH output to one specific vault. Using vaultId as the HKDF salt
 * means a share row lifted from vault A cannot be replayed onto vault B, even
 * though both were wrapped to the same recipient with the same ephemeral key.
 */
async function deriveShareWrapKey(ephemeralPrivate, recipientPublic, vaultId) {
    const shared = new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'ECDH', public: recipientPublic }, ephemeralPrivate, 256
    ));
    const wrapBytes = await hkdf(shared, HKDF_INFO_VAULT_SHARE, TEXT.encode(String(vaultId)));
    shared.fill(0);
    const key = await crypto.subtle.importKey(
        'raw', wrapBytes, { name: ENCRYPTION_ALGORITHM }, false, ['encrypt', 'decrypt']
    );
    wrapBytes.fill(0);
    return key;
}

/**
 * ECIES-wraps a vault key for one recipient. Granting access is then a single
 * row insert — the recipient does not have to be online, and no vault
 * ciphertext is touched.
 *
 * @returns {Promise<{wrappedKey: string, ephemeralPubkey: string}>}
 */
export async function wrapVaultKey(vaultId, recipientPublicKeyB64, vaultKey) {
    const recipientPublic = await importPublicKey(recipientPublicKeyB64);
    // Fresh ephemeral keypair per share: reusing one across recipients would let
    // any two of them derive each other's wrap keys.
    const ephemeral = await crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveBits']);
    const wrapKey = await deriveShareWrapKey(ephemeral.privateKey, recipientPublic, vaultId);

    const rawVaultKey = new Uint8Array(await crypto.subtle.exportKey('raw', vaultKey));
    const wrappedKey = await sealRaw(wrapKey, rawVaultKey);
    rawVaultKey.fill(0);

    const ephSpki = new Uint8Array(await crypto.subtle.exportKey('spki', ephemeral.publicKey));
    return { wrappedKey, ephemeralPubkey: bytesToBase64(ephSpki) };
}

/**
 * Reverses wrapVaultKey using the member's own private key.
 *
 * @param {{wrapped_key: string, ephemeral_pubkey: string}} share  A vault_key_shares row.
 * @returns {Promise<CryptoKey>} the vault key, extractable so it can be re-wrapped on grant
 */
export async function unwrapVaultKey(vaultId, myPrivateKey, share) {
    const ephemeralPublic = await importPublicKey(share.ephemeral_pubkey);
    const wrapKey = await deriveShareWrapKey(myPrivateKey, ephemeralPublic, vaultId);
    const raw = await openRaw(wrapKey, share.wrapped_key);
    const key = await crypto.subtle.importKey(
        'raw', raw, { name: ENCRYPTION_ALGORITHM }, true, ['encrypt', 'decrypt']
    );
    raw.fill(0);
    return key;
}

/**
 * Wraps one vault key for many recipients — the shape every grant path needs
 * (vault creation, adding an org member, rotating after a revoke).
 *
 * @param {Array<{userId: number, publicKey: string}>} members
 * @returns {Promise<Array<{userId: number, wrappedKey: string, ephemeralPubkey: string}>>}
 */
export async function wrapVaultKeyForMembers(vaultId, vaultKey, members) {
    return Promise.all(members.map(async ({ userId, publicKey }) => ({
        userId,
        ...(await wrapVaultKey(vaultId, publicKey, vaultKey))
    })));
}
