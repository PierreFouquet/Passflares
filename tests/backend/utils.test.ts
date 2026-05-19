import { describe, it, expect } from 'vitest';
import {
    uint8ArrayToHexString,
    hexStringToUint8Array,
    jsonResponse,
    deriveScryptHash
} from '../../src/utils.js';

describe('uint8ArrayToHexString', () => {
    it('converts a known byte array to hex', () => {
        const input = new Uint8Array([0, 1, 15, 16, 255]);
        expect(uint8ArrayToHexString(input)).toBe('00010f10ff');
    });

    it('returns an empty string for an empty array', () => {
        expect(uint8ArrayToHexString(new Uint8Array([]))).toBe('');
    });
});

describe('hexStringToUint8Array', () => {
    it('converts a hex string back to the original bytes', () => {
        const hex = '00010f10ff';
        const result = hexStringToUint8Array(hex);
        expect(Array.from(result)).toEqual([0, 1, 15, 16, 255]);
    });

    it('throws on an odd-length hex string', () => {
        expect(() => hexStringToUint8Array('abc')).toThrow();
    });

    it('is the inverse of uint8ArrayToHexString', () => {
        const original = new Uint8Array([42, 99, 200, 0, 7]);
        const roundtrip = hexStringToUint8Array(uint8ArrayToHexString(original));
        expect(Array.from(roundtrip)).toEqual(Array.from(original));
    });
});

describe('jsonResponse', () => {
    it('returns a 200 response with JSON body by default', async () => {
        const res = jsonResponse({ message: 'ok' });
        expect(res.status).toBe(200);
        expect(res.headers.get('Content-Type')).toBe('application/json');
        const body = await res.json();
        expect(body).toEqual({ message: 'ok' });
    });

    it('respects a custom status code', async () => {
        const res = jsonResponse({ message: 'created' }, 201);
        expect(res.status).toBe(201);
    });

    it('returns correct body for a 400 error', async () => {
        const res = jsonResponse({ message: 'bad request' }, 400);
        const body = await res.json();
        expect(body.message).toBe('bad request');
    });
});

describe('deriveScryptHash', () => {
    it('returns a hash and a salt as hex strings', async () => {
        const { hash, salt } = await deriveScryptHash('password123');
        expect(hash).toMatch(/^[0-9a-f]+$/);
        expect(salt).toMatch(/^[0-9a-f]+$/);
    }, 30_000);

    it('produces the same hash when given the same salt', async () => {
        const { hash: hash1, salt } = await deriveScryptHash('mypassword');
        const { hash: hash2 } = await deriveScryptHash('mypassword', salt);
        expect(hash1).toBe(hash2);
    }, 30_000);

    it('produces different hashes for different passwords', async () => {
        const { hash: hash1, salt } = await deriveScryptHash('password-A');
        const { hash: hash2 } = await deriveScryptHash('password-B', salt);
        expect(hash1).not.toBe(hash2);
    }, 30_000);
}, 60_000);
