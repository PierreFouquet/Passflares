// public/js/kdf-worker.js — Argon2id off the UI thread.
//
// Argon2id at the OWASP first-choice profile costs ~1-1.5 s and ~46 MB in a
// browser. On the main thread that is a frozen tab during login; here the page
// stays responsive and can show progress.
//
// Message in:  { id, password, saltHex, params: { m, t, p, len } }
// Message out: { id, ok: true, keyHex } | { id, ok: false, error }
//
// The worker deliberately deals in hex strings rather than CryptoKey objects:
// CryptoKey is not structured-cloneable across a worker boundary, so the caller
// (public/js/keys.js) imports the raw bytes on the main thread.

import { argon2id } from '../vendor/noble-hashes/argon2.js';

function hexToBytes(hex) {
    if (hex.length % 2 !== 0) throw new Error('Hex string must have an even number of characters.');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

self.addEventListener('message', (event) => {
    const { id, password, saltHex, params } = event.data ?? {};
    try {
        const derived = argon2id(
            new TextEncoder().encode(password),
            hexToBytes(saltHex),
            { m: params.m, t: params.t, p: params.p, dkLen: params.len }
        );
        const keyHex = bytesToHex(derived);
        derived.fill(0);
        self.postMessage({ id, ok: true, keyHex });
    } catch (error) {
        self.postMessage({ id, ok: false, error: error?.message ?? 'Key derivation failed.' });
    }
});
