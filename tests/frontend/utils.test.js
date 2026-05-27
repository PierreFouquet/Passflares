// @vitest-environment happy-dom
import { describe, it, expect } from 'vitest';
import {
    uint8ArrayToHexString,
    hexStringToUint8Array,
    generateSalt,
    checkPasswordStrength,
    generateRandomPassword,
    searchVaultEntries,
    copyToClipboard
} from '../../public/js/utils.js';

describe('uint8ArrayToHexString', () => {
    it('converts bytes to a lowercase hex string', () => {
        expect(uint8ArrayToHexString(new Uint8Array([0, 255, 16]))).toBe('00ff10');
    });
});

describe('hexStringToUint8Array', () => {
    it('converts a hex string back to bytes', () => {
        const result = hexStringToUint8Array('00ff10');
        expect(Array.from(result)).toEqual([0, 255, 16]);
    });

    it('throws on an odd-length string', () => {
        expect(() => hexStringToUint8Array('abc')).toThrow();
    });
});

describe('generateSalt', () => {
    it('returns a Uint8Array of the correct default length', () => {
        const salt = generateSalt();
        expect(salt).toBeInstanceOf(Uint8Array);
        expect(salt.length).toBe(16);
    });

    it('respects a custom length', () => {
        expect(generateSalt(32).length).toBe(32);
    });

    it('returns different values each call', () => {
        const a = generateSalt();
        const b = generateSalt();
        expect(uint8ArrayToHexString(a)).not.toBe(uint8ArrayToHexString(b));
    });
});

describe('checkPasswordStrength', () => {
    it('rates a short simple password as weak', () => {
        const { strength } = checkPasswordStrength('abc');
        expect(['Very Weak', 'Weak']).toContain(strength);
    });

    it('rates a strong password as Strong or Excellent', () => {
        const { strength, score } = checkPasswordStrength('MyS3cur3P@ssw0rd!');
        expect(score).toBeGreaterThanOrEqual(5);
        expect(['Strong', 'Excellent']).toContain(strength);
    });

    it('indicates a weak password does not meet requirements', () => {
        const { meetsMinRequirements } = checkPasswordStrength('short');
        expect(meetsMinRequirements).toBe(false);
    });

    it('indicates a strong password meets requirements', () => {
        const { meetsMinRequirements } = checkPasswordStrength('MyS3cur3P@ssw0rd!');
        expect(meetsMinRequirements).toBe(true);
    });
});

describe('generateRandomPassword', () => {
    it('returns a string of the correct default length', () => {
        expect(generateRandomPassword()).toHaveLength(16);
    });

    it('respects a custom length', () => {
        expect(generateRandomPassword(24)).toHaveLength(24);
    });

    it('contains at least one lowercase, uppercase, number, and symbol', () => {
        const password = generateRandomPassword(20);
        expect(password).toMatch(/[a-z]/);
        expect(password).toMatch(/[A-Z]/);
        expect(password).toMatch(/[0-9]/);
        expect(password).toMatch(/[^A-Za-z0-9]/);
    });

    it('generates different passwords each call', () => {
        expect(generateRandomPassword()).not.toBe(generateRandomPassword());
    });

    it('coerces length < 4 up to 4 (cannot satisfy class requirements otherwise)', () => {
        expect(generateRandomPassword(2)).toHaveLength(4);
        expect(generateRandomPassword(0)).toHaveLength(4);
    });

    it('uses crypto.getRandomValues, not Math.random (regression — CodeQL js/insecure-randomness)', () => {
        // Math.random must never be called from password generation. If it
        // ever returns, a future regression has re-introduced a CSPRNG
        // weakness for the master-vault password generator.
        const origRandom = Math.random;
        let mathRandomCalls = 0;
        try {
            Math.random = () => { mathRandomCalls++; return 0.5; };
            for (let i = 0; i < 5; i++) generateRandomPassword(20);
        } finally {
            Math.random = origRandom;
        }
        expect(mathRandomCalls).toBe(0);
    });

    it('actually invokes crypto.getRandomValues at least once per call', () => {
        const origGetRandomValues = crypto.getRandomValues.bind(crypto);
        let calls = 0;
        crypto.getRandomValues = (buf) => { calls++; return origGetRandomValues(buf); };
        try {
            generateRandomPassword(16);
        } finally {
            crypto.getRandomValues = origGetRandomValues;
        }
        expect(calls).toBeGreaterThanOrEqual(16);
    });

    it('shuffle does not pin the lowercase/upper/digit/symbol seeds at positions 0..3', () => {
        // The old Math.random()-based sort was both biased and non-CSPRNG.
        // The Fisher-Yates replacement must actually move characters around,
        // so the first four positions are not always (lower, upper, digit,
        // symbol). Statistically that ordering should appear < 1% of the
        // time across many runs.
        let pinnedCount = 0;
        const N = 200;
        for (let i = 0; i < N; i++) {
            const p = generateRandomPassword(20);
            if (/^[a-z][A-Z][0-9][^A-Za-z0-9]/.test(p)) pinnedCount++;
        }
        // With a uniform shuffle the expected hit rate is ~ 1 / 116,280
        // (= 4! / 20·19·18·17 for the right slot picks across the 20-char
        // permutation), so any nonzero rate above ~5/200 here is suspicious.
        expect(pinnedCount).toBeLessThan(5);
    });
});

describe('searchVaultEntries', () => {
    const entries = [
        { id: '1', name: 'GitHub', username: 'pierre', url: 'https://github.com', notes: 'Work account' },
        { id: '2', name: 'Gmail', username: 'pierre@gmail.com', url: 'https://mail.google.com', notes: '' },
        { id: '3', name: 'AWS Console', username: 'admin', url: 'https://aws.amazon.com', notes: 'Production' }
    ];

    it('finds entries by name (case-insensitive)', () => {
        expect(searchVaultEntries('github', entries)).toHaveLength(1);
        expect(searchVaultEntries('GMAIL', entries)).toHaveLength(1);
    });

    it('finds entries by username', () => {
        expect(searchVaultEntries('pierre', entries)).toHaveLength(2);
    });

    it('finds entries by URL', () => {
        expect(searchVaultEntries('google', entries)).toHaveLength(1);
    });

    it('finds entries by notes', () => {
        expect(searchVaultEntries('production', entries)).toHaveLength(1);
    });

    it('returns an empty array when no entries match', () => {
        expect(searchVaultEntries('zzznomatch', entries)).toHaveLength(0);
    });

    it('returns all entries when query matches all', () => {
        // 'a' appears in GitHub (username pierre has no a), Gmail, AWS - let's use 'https'
        expect(searchVaultEntries('https', entries)).toHaveLength(3);
    });
});
