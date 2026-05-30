// Pure-logic tests for the TOTP helpers in src/totp.ts — code generation,
// verification window, recovery-code format/hashing, and secret encryption.
import { describe, it, expect, vi } from 'vitest';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

import { TOTP, Secret } from 'otpauth';
import { __testables } from '../../src/totp.js';
import { createMockEnv } from '../mocks/cloudflare.js';

const {
    normalizeRecoveryCode,
    hashRecoveryCode,
    generateRecoveryCodes,
    verifyTotpToken,
    totpUri,
    qrDataUri,
    encryptSecret,
    decryptSecret,
    RECOVERY_CODE_ALPHABET,
    RECOVERY_CODE_COUNT
} = __testables;

const env = createMockEnv({ TOTP_ENC_KEY: 'unit-test-totp-enc-key-32-chars-min!!' }) as any;

// Helper: a valid current code for a given base32 secret.
function currentCode(base32: string): string {
    return new TOTP({ secret: Secret.fromBase32(base32), digits: 6, period: 30, algorithm: 'SHA1' }).generate();
}

describe('TOTP code verification', () => {
    const secret = new Secret({ size: 20 }).base32;

    it('accepts a freshly generated current code', () => {
        expect(verifyTotpToken(secret, 'a@b.com', currentCode(secret))).toBe(true);
    });

    it('rejects an obviously wrong code', () => {
        expect(verifyTotpToken(secret, 'a@b.com', '000000')).toBe(false);
    });

    it('rejects non-6-digit input', () => {
        expect(verifyTotpToken(secret, 'a@b.com', '12345')).toBe(false);
        expect(verifyTotpToken(secret, 'a@b.com', 'abcdef')).toBe(false);
    });

    it('tolerates whitespace in the submitted code', () => {
        const code = currentCode(secret);
        expect(verifyTotpToken(secret, 'a@b.com', ` ${code} `)).toBe(true);
    });

    it('rejects a code from a different secret', () => {
        const other = new Secret({ size: 20 }).base32;
        expect(verifyTotpToken(secret, 'a@b.com', currentCode(other))).toBe(false);
    });
});

describe('otpauth URI + QR', () => {
    const secret = new Secret({ size: 20 }).base32;

    it('builds a well-formed otpauth URI', () => {
        const uri = totpUri(secret, 'user@example.com');
        expect(uri.startsWith('otpauth://totp/')).toBe(true);
        expect(uri).toContain('issuer=Passflares');
        expect(uri).toContain(`secret=${secret}`);
    });

    it('renders a QR as an SVG data URI', () => {
        const dataUri = qrDataUri(totpUri(secret, 'user@example.com'));
        expect(dataUri.startsWith('data:image/svg+xml;base64,')).toBe(true);
        const svg = atob(dataUri.split(',')[1]);
        expect(svg).toContain('<svg');
    });
});

describe('recovery codes', () => {
    it('generates the configured count', () => {
        expect(generateRecoveryCodes()).toHaveLength(RECOVERY_CODE_COUNT);
        expect(generateRecoveryCodes(3)).toHaveLength(3);
    });

    it('uses only the unambiguous alphabet and XXXXX-XXXXX shape', () => {
        const re = new RegExp(`^[${RECOVERY_CODE_ALPHABET}]{5}-[${RECOVERY_CODE_ALPHABET}]{5}$`);
        for (const code of generateRecoveryCodes()) {
            expect(code).toMatch(re);
        }
    });

    it('produces unique codes', () => {
        const codes = generateRecoveryCodes(50);
        expect(new Set(codes).size).toBe(codes.length);
    });

    it('normalizes case, dashes and spaces consistently', () => {
        expect(normalizeRecoveryCode('abcde-fghjk')).toBe('ABCDEFGHJK');
        expect(normalizeRecoveryCode(' ABCDE FGHJK ')).toBe('ABCDEFGHJK');
    });

    it('hashes equal (normalized) codes to the same value, different codes differ', () => {
        expect(hashRecoveryCode(env, 'abcde-fghjk')).toBe(hashRecoveryCode(env, 'ABCDEFGHJK'));
        expect(hashRecoveryCode(env, 'ABCDE-FGHJK')).not.toBe(hashRecoveryCode(env, 'ABCDE-FGHJM'));
    });

    it('hash is keyed by TOTP_ENC_KEY (different key → different hash)', () => {
        const env2 = createMockEnv({ TOTP_ENC_KEY: 'a-totally-different-key-value-here!!' }) as any;
        expect(hashRecoveryCode(env, 'ABCDE-FGHJK')).not.toBe(hashRecoveryCode(env2, 'ABCDE-FGHJK'));
    });
});

describe('secret encryption at rest', () => {
    it('round-trips a base32 secret', async () => {
        const secret = new Secret({ size: 20 }).base32;
        const enc = await encryptSecret(env, secret);
        expect(enc.startsWith('v1:')).toBe(true);
        expect(enc).not.toContain(secret);
        expect(await decryptSecret(env, enc)).toBe(secret);
    });

    it('produces a different ciphertext each time (random IV)', async () => {
        const secret = new Secret({ size: 20 }).base32;
        expect(await encryptSecret(env, secret)).not.toBe(await encryptSecret(env, secret));
    });

    it('fails to decrypt tampered ciphertext (GCM auth)', async () => {
        const enc = await encryptSecret(env, new Secret({ size: 20 }).base32);
        const [v, iv, ct] = enc.split(':');
        const flipped = ct.slice(0, -2) + (ct.slice(-2) === 'ff' ? '00' : 'ff');
        await expect(decryptSecret(env, `${v}:${iv}:${flipped}`)).rejects.toBeTruthy();
    });

    it('rejects an unknown format prefix', async () => {
        await expect(decryptSecret(env, 'v2:aa:bb')).rejects.toBeTruthy();
    });
});
