// @vitest-environment happy-dom
import { describe, it, expect } from 'vitest';
import { deriveKey, encryptData, decryptData } from '../../public/js/crypto.js';
import { uint8ArrayToHexString, generateSalt } from '../../public/js/utils.js';

const MASTER_PASSWORD = 'TestMasterPassword123!';

async function freshKey() {
    const salt = uint8ArrayToHexString(generateSalt());
    return { key: await deriveKey(MASTER_PASSWORD, salt), salt };
}

// --- deriveKey ---

describe('deriveKey', () => {
    it('returns a CryptoKey', async () => {
        const { key } = await freshKey();
        expect(key).toBeDefined();
        expect(typeof key).toBe('object');
    });

    it('produces the same key from the same password and salt', async () => {
        const salt = uint8ArrayToHexString(generateSalt());
        const key1 = await deriveKey(MASTER_PASSWORD, salt);
        const key2 = await deriveKey(MASTER_PASSWORD, salt);

        // Export both keys and compare raw bytes
        const raw1 = await crypto.subtle.exportKey('raw', key1);
        const raw2 = await crypto.subtle.exportKey('raw', key2);
        expect(new Uint8Array(raw1)).toEqual(new Uint8Array(raw2));
    });

    it('produces different keys for different passwords', async () => {
        const salt = uint8ArrayToHexString(generateSalt());
        const key1 = await deriveKey('PasswordA!!1', salt);
        const key2 = await deriveKey('PasswordB!!2', salt);

        const raw1 = await crypto.subtle.exportKey('raw', key1);
        const raw2 = await crypto.subtle.exportKey('raw', key2);
        expect(new Uint8Array(raw1)).not.toEqual(new Uint8Array(raw2));
    });

    it('produces different keys for different salts', async () => {
        const key1 = await deriveKey(MASTER_PASSWORD, uint8ArrayToHexString(generateSalt()));
        const key2 = await deriveKey(MASTER_PASSWORD, uint8ArrayToHexString(generateSalt()));

        const raw1 = await crypto.subtle.exportKey('raw', key1);
        const raw2 = await crypto.subtle.exportKey('raw', key2);
        expect(new Uint8Array(raw1)).not.toEqual(new Uint8Array(raw2));
    });
});

// --- encryptData ---

describe('encryptData', () => {
    it('returns an object with iv and ciphertext as hex strings', async () => {
        const { key } = await freshKey();
        const result = await encryptData({ secret: 'value' }, key);

        expect(result).toHaveProperty('iv');
        expect(result).toHaveProperty('ciphertext');
        expect(result.iv).toMatch(/^[0-9a-f]+$/);
        expect(result.ciphertext).toMatch(/^[0-9a-f]+$/);
    });

    it('produces different ciphertext each call (random IV)', async () => {
        const { key } = await freshKey();
        const data = { secret: 'same data' };
        const r1 = await encryptData(data, key);
        const r2 = await encryptData(data, key);

        expect(r1.iv).not.toBe(r2.iv);
        expect(r1.ciphertext).not.toBe(r2.ciphertext);
    });
});

// --- decryptData ---

describe('decryptData', () => {
    it('decrypts data back to the original plaintext', async () => {
        const { key } = await freshKey();
        const original = { username: 'pierre', password: 'hunter2', url: 'https://example.com' };

        const encrypted = await encryptData(original, key);
        const decrypted = await decryptData(encrypted, key);

        expect(decrypted).toEqual(original);
    });

    it('decrypts an array of entries correctly', async () => {
        const { key } = await freshKey();
        const entries = [
            { id: '1', name: 'GitHub', username: 'user', password: 'pass1' },
            { id: '2', name: 'Gmail', username: 'user@gmail.com', password: 'pass2' }
        ];

        const encrypted = await encryptData(entries, key);
        const decrypted = await decryptData(encrypted, key);

        expect(decrypted).toEqual(entries);
    });

    it('throws when decrypting with the wrong key', async () => {
        const { key: encKey } = await freshKey();
        const { key: wrongKey } = await freshKey();

        const encrypted = await encryptData({ secret: 'data' }, encKey);

        await expect(decryptData(encrypted, wrongKey)).rejects.toThrow();
    });

    it('throws when the ciphertext is tampered with', async () => {
        const { key } = await freshKey();
        const encrypted = await encryptData({ secret: 'data' }, key);
        const tampered = { ...encrypted, ciphertext: encrypted.ciphertext.slice(0, -4) + 'dead' };

        await expect(decryptData(tampered, key)).rejects.toThrow();
    });
});
