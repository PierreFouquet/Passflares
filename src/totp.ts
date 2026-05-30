// src/totp.ts
//
// TOTP (RFC 6238) two-factor authentication + single-use recovery codes.
//
// Design notes:
//   - TOTP secrets are encrypted at rest (AES-GCM) with a key derived from the
//     TOTP_ENC_KEY worker secret, so a D1-only leak doesn't expose them. We
//     fail closed if TOTP_ENC_KEY is unset rather than storing plaintext.
//   - Recovery codes are high-entropy, so they're hashed with a fast peppered
//     HMAC-SHA256 (not scrypt) — this allows an O(1) indexed lookup and avoids
//     running heavy scrypt up to 10x per recovery login on the Worker.
//   - Login is two-step: handleLogin issues a short-lived token scoped to '2fa';
//     handleLoginVerify2fa exchanges it (plus a TOTP or recovery code) for the
//     real session token. The auth middleware rejects scope:'2fa' on protected
//     routes so the temp token can never reach vault data.

import { sign, verify } from 'jsonwebtoken';
import { TOTP, Secret } from 'otpauth';
import QRCode from 'qrcode-svg';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { CustomRequest, Env } from './types.js';
import {
    deriveScryptHash,
    hexStringToUint8Array,
    uint8ArrayToHexString,
    jsonResponse
} from './utils.js';
import { logAudit } from './auditLog.js';

const FAILED_ATTEMPTS_LIMIT = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes (matches auth.ts)
const TEMP_TOKEN_TTL = '5m';
const SESSION_TOKEN_TTL = '1h';
const RECOVERY_CODE_COUNT = 10;
// 32 unambiguous characters (no I, O, 0, 1). 256 % 32 === 0, so picking by
// `byte % 32` is unbiased.
const RECOVERY_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const TOTP_ISSUER = 'Passflares';

interface TotpRow {
    user_id: number;
    secret_enc: string | null;
    pending_secret_enc: string | null;
    enabled: number; // 0 | 1
    confirmed_at: string | null;
}

// ─── key material (derived from TOTP_ENC_KEY) ───────────────────────────────

function encKeyMaterial(env: Env): Uint8Array {
    // Fail closed — never silently fall back to storing/verifying secrets
    // without the encryption key configured.
    if (!env.TOTP_ENC_KEY) {
        throw new Error('TOTP_ENC_KEY is not configured.');
    }
    return new TextEncoder().encode(env.TOTP_ENC_KEY);
}

// HKDF gives domain-separated subkeys from the single TOTP_ENC_KEY secret:
// one for AES-GCM secret encryption, one for recovery-code HMAC.
function subkey(env: Env, info: string): Uint8Array {
    return hkdf(sha256, encKeyMaterial(env), new Uint8Array(0), new TextEncoder().encode(info), 32);
}

async function aesKey(env: Env): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        'raw',
        subkey(env, 'passflares:totp:aes-gcm'),
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptSecret(env: Env, base32: string): Promise<string> {
    const key = await aesKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(base32));
    return `v1:${uint8ArrayToHexString(iv)}:${uint8ArrayToHexString(new Uint8Array(ct))}`;
}

async function decryptSecret(env: Env, stored: string): Promise<string> {
    const parts = stored.split(':');
    if (parts.length !== 3 || parts[0] !== 'v1') {
        throw new Error('Unsupported TOTP secret format.');
    }
    const key = await aesKey(env);
    const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: hexStringToUint8Array(parts[1]) },
        key,
        hexStringToUint8Array(parts[2])
    );
    return new TextDecoder().decode(pt);
}

// ─── recovery codes ─────────────────────────────────────────────────────────

function normalizeRecoveryCode(code: string): string {
    return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function hashRecoveryCode(env: Env, code: string): string {
    const key = subkey(env, 'passflares:recovery:hmac');
    return uint8ArrayToHexString(hmac(sha256, key, new TextEncoder().encode(normalizeRecoveryCode(code))));
}

function generateRecoveryCodes(count = RECOVERY_CODE_COUNT): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
        const bytes = randomBytes(10);
        let s = '';
        for (const b of bytes) s += RECOVERY_CODE_ALPHABET[b % RECOVERY_CODE_ALPHABET.length];
        codes.push(`${s.slice(0, 5)}-${s.slice(5)}`);
    }
    return codes;
}

// ─── TOTP ───────────────────────────────────────────────────────────────────

function buildTotp(secretBase32: string, label: string): TOTP {
    return new TOTP({
        issuer: TOTP_ISSUER,
        label: label || 'account',
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: Secret.fromBase32(secretBase32)
    });
}

// window:1 tolerates ~±30s of clock drift between server and authenticator.
function verifyTotpToken(secretBase32: string, label: string, token: string): boolean {
    const normalized = String(token).replace(/\s+/g, '');
    if (!/^\d{6}$/.test(normalized)) return false;
    return buildTotp(secretBase32, label).validate({ token: normalized, window: 1 }) !== null;
}

function totpUri(secretBase32: string, label: string): string {
    return buildTotp(secretBase32, label).toString();
}

function qrDataUri(uri: string): string {
    const svg = new QRCode({ content: uri, padding: 2, width: 220, height: 220, ecl: 'M', join: true }).svg();
    // img-src 'self' data: is allowed by the HTML CSP (see src/worker.ts).
    return `data:image/svg+xml;base64,${btoa(svg)}`;
}

// ─── DB helpers (all static SQL strings + bound params) ──────────────────────

async function getTotpRow(env: Env, userId: number): Promise<TotpRow | null> {
    return env.DB.prepare(
        'SELECT user_id, secret_enc, pending_secret_enc, enabled, confirmed_at FROM user_totp WHERE user_id = ?'
    ).bind(userId).first<TotpRow>();
}

async function countUnusedRecoveryCodes(env: Env, userId: number): Promise<number> {
    const row = await env.DB.prepare(
        'SELECT COUNT(*) AS cnt FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL'
    ).bind(userId).first<{ cnt: number }>();
    return row?.cnt ?? 0;
}

async function replaceRecoveryCodes(env: Env, userId: number, codes: string[]): Promise<void> {
    await env.DB.prepare('DELETE FROM user_recovery_codes WHERE user_id = ?').bind(userId).run();
    const insert = env.DB.prepare('INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)');
    await env.DB.batch(codes.map(c => insert.bind(userId, hashRecoveryCode(env, c))));
}

async function consumeRecoveryCode(env: Env, userId: number, code: string): Promise<boolean> {
    const hash = hashRecoveryCode(env, code);
    const row = await env.DB.prepare(
        'SELECT id FROM user_recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL'
    ).bind(userId, hash).first<{ id: number }>();
    if (!row) return false;
    await env.DB.prepare('UPDATE user_recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ?').bind(row.id).run();
    return true;
}

async function verifyMasterPassword(env: Env, userId: number, masterPassword: string): Promise<boolean> {
    const u = await env.DB.prepare('SELECT password_hash, password_salt FROM users WHERE id = ?')
        .bind(userId).first<{ password_hash: string; password_salt: string }>();
    if (!u) return false;
    const { hash } = await deriveScryptHash(masterPassword, u.password_salt);
    return hash === u.password_hash;
}

// Accepts the active TOTP code or an unused recovery code (consuming the latter).
// Used to re-authorize sensitive 2FA changes (disable / switch authenticator).
async function verifyActiveSecondFactor(env: Env, userId: number, row: TotpRow, label: string, code: string): Promise<boolean> {
    if (row.secret_enc) {
        const secret = await decryptSecret(env, row.secret_enc);
        if (verifyTotpToken(secret, label, code)) return true;
    }
    return consumeRecoveryCode(env, userId, code);
}

// ─── rate limiting (reuses the KV pattern from auth.ts) ──────────────────────

async function isRateLimited(env: Env, key: string): Promise<boolean> {
    const v = await env.RATE_LIMIT.get(key);
    return !!v && parseInt(v) >= FAILED_ATTEMPTS_LIMIT;
}

async function bumpFailure(env: Env, key: string): Promise<void> {
    const v = await env.RATE_LIMIT.get(key);
    const n = v ? parseInt(v) + 1 : 1;
    await env.RATE_LIMIT.put(key, String(n), { expirationTtl: LOCKOUT_DURATION / 1000 });
}

async function clearFailures(env: Env, key: string): Promise<void> {
    await env.RATE_LIMIT.delete(key);
}

async function safeJson(request: CustomRequest): Promise<Record<string, any>> {
    try {
        return (await request.json()) as Record<string, any>;
    } catch {
        return {};
    }
}

// ─── handlers ────────────────────────────────────────────────────────────────

export async function handleTotpStatus(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const userId = request.user!.userId;
    try {
        const row = await getTotpRow(env, userId);
        const enabled = row?.enabled === 1;
        const remainingRecoveryCodes = enabled ? await countUnusedRecoveryCodes(env, userId) : 0;
        return jsonResponse({ enabled, remainingRecoveryCodes });
    } catch (error: any) {
        console.error('TOTP status error:', error);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}

export async function handleTotpEnroll(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const userId = request.user!.userId;
    const email = request.user!.email;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');
    try {
        const row = await getTotpRow(env, userId);

        // Switching to a new authenticator while 2FA is active requires re-auth
        // (master password + a current code). The active secret stays valid
        // until the new one is confirmed, so there's no lockout window.
        if (row?.enabled === 1) {
            const { masterPassword, code } = await safeJson(request);
            if (!masterPassword || !code) {
                return jsonResponse({ message: 'Master password and a current code are required to change your authenticator.' }, 400);
            }
            if (!(await verifyMasterPassword(env, userId, masterPassword))) {
                logAudit(env, ctx, userId, 'TOTP_ENROLL_FAILURE', { reason: 'Password mismatch' }, ipAddress, userAgent);
                return jsonResponse({ message: 'Master password is incorrect.' }, 401);
            }
            if (!(await verifyActiveSecondFactor(env, userId, row, email, code))) {
                logAudit(env, ctx, userId, 'TOTP_ENROLL_FAILURE', { reason: 'Invalid second factor' }, ipAddress, userAgent);
                return jsonResponse({ message: 'Invalid authenticator or recovery code.' }, 401);
            }
        }

        const secret = new Secret({ size: 20 }).base32;
        const enc = await encryptSecret(env, secret);
        await env.DB.prepare(
            'INSERT INTO user_totp (user_id, pending_secret_enc, enabled, updated_at) VALUES (?, ?, 0, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET pending_secret_enc = excluded.pending_secret_enc, updated_at = CURRENT_TIMESTAMP'
        ).bind(userId, enc).run();

        const uri = totpUri(secret, email);
        logAudit(env, ctx, userId, 'TOTP_ENROLL_START', { change: row?.enabled === 1 }, ipAddress, userAgent);
        return jsonResponse({ secret, otpauthUri: uri, qrDataUri: qrDataUri(uri) });
    } catch (error: any) {
        console.error('TOTP enroll error:', error);
        logAudit(env, ctx, userId, 'TOTP_ENROLL_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}

export async function handleTotpEnable(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const userId = request.user!.userId;
    const email = request.user!.email;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');
    try {
        const { code } = await safeJson(request);
        if (!code) return jsonResponse({ message: 'A verification code is required.' }, 400);

        const row = await getTotpRow(env, userId);
        if (!row?.pending_secret_enc) {
            return jsonResponse({ message: 'No 2FA enrollment in progress.' }, 400);
        }

        const pendingSecret = await decryptSecret(env, row.pending_secret_enc);
        if (!verifyTotpToken(pendingSecret, email, code)) {
            logAudit(env, ctx, userId, 'TOTP_ENABLE_FAILURE', { reason: 'Invalid code' }, ipAddress, userAgent);
            return jsonResponse({ message: 'That code is not valid. Try again.' }, 401);
        }

        const wasEnabled = row.enabled === 1;
        await env.DB.prepare(
            'UPDATE user_totp SET secret_enc = pending_secret_enc, pending_secret_enc = NULL, enabled = 1, confirmed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?'
        ).bind(userId).run();

        // Switching authenticators keeps the existing recovery codes; only a
        // first-time enable issues a fresh set.
        if (wasEnabled) {
            logAudit(env, ctx, userId, 'TOTP_CHANGED', {}, ipAddress, userAgent);
            return jsonResponse({ changed: true, message: 'Authenticator updated.' });
        }

        const recoveryCodes = generateRecoveryCodes();
        await replaceRecoveryCodes(env, userId, recoveryCodes);
        logAudit(env, ctx, userId, 'TOTP_ENABLED', {}, ipAddress, userAgent);
        return jsonResponse({ enabled: true, recoveryCodes });
    } catch (error: any) {
        console.error('TOTP enable error:', error);
        logAudit(env, ctx, userId, 'TOTP_ENABLE_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}

export async function handleTotpDisable(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const userId = request.user!.userId;
    const email = request.user!.email;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');
    try {
        const { masterPassword, code } = await safeJson(request);
        if (!masterPassword || !code) {
            return jsonResponse({ message: 'Master password and a current code are required.' }, 400);
        }
        const row = await getTotpRow(env, userId);
        if (row?.enabled !== 1) {
            return jsonResponse({ message: 'Two-factor authentication is not enabled.' }, 400);
        }
        if (!(await verifyMasterPassword(env, userId, masterPassword))) {
            logAudit(env, ctx, userId, 'TOTP_DISABLE_FAILURE', { reason: 'Password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: 'Master password is incorrect.' }, 401);
        }
        if (!(await verifyActiveSecondFactor(env, userId, row, email, code))) {
            logAudit(env, ctx, userId, 'TOTP_DISABLE_FAILURE', { reason: 'Invalid second factor' }, ipAddress, userAgent);
            return jsonResponse({ message: 'Invalid authenticator or recovery code.' }, 401);
        }

        await env.DB.prepare('DELETE FROM user_recovery_codes WHERE user_id = ?').bind(userId).run();
        await env.DB.prepare('DELETE FROM user_totp WHERE user_id = ?').bind(userId).run();
        logAudit(env, ctx, userId, 'TOTP_DISABLED', {}, ipAddress, userAgent);
        return jsonResponse({ disabled: true, message: 'Two-factor authentication disabled.' });
    } catch (error: any) {
        console.error('TOTP disable error:', error);
        logAudit(env, ctx, userId, 'TOTP_DISABLE_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}

export async function handleRegenerateRecoveryCodes(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const userId = request.user!.userId;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');
    try {
        const { masterPassword } = await safeJson(request);
        if (!masterPassword) {
            return jsonResponse({ message: 'Master password is required.' }, 400);
        }
        const row = await getTotpRow(env, userId);
        if (row?.enabled !== 1) {
            return jsonResponse({ message: 'Two-factor authentication is not enabled.' }, 400);
        }
        if (!(await verifyMasterPassword(env, userId, masterPassword))) {
            logAudit(env, ctx, userId, 'RECOVERY_CODES_REGENERATE_FAILURE', { reason: 'Password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: 'Master password is incorrect.' }, 401);
        }
        const recoveryCodes = generateRecoveryCodes();
        await replaceRecoveryCodes(env, userId, recoveryCodes);
        logAudit(env, ctx, userId, 'RECOVERY_CODES_REGENERATED', {}, ipAddress, userAgent);
        return jsonResponse({ recoveryCodes });
    } catch (error: any) {
        console.error('Recovery code regeneration error:', error);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}

// Second login step: exchange the scope:'2fa' temp token + a TOTP/recovery code
// for a real session token. Public route (no withAuth) — the temp token is the
// proof that the password was already verified in handleLogin.
export async function handleLoginVerify2fa(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');
    const { tempToken, code } = await safeJson(request);

    if (!tempToken || !code) {
        return jsonResponse({ message: 'Verification code is required.' }, 400);
    }

    const ipKey = `rate_limit:2fa:${ipAddress}`;
    if (await isRateLimited(env, ipKey)) {
        logAudit(env, ctx, null, 'LOGIN_2FA_FAILURE', { reason: 'Rate limited' }, ipAddress, userAgent);
        return jsonResponse({ message: 'Too many attempts. Try again later.' }, 429);
    }

    let decoded: { sub?: number; email?: string; scope?: string };
    try {
        decoded = verify(tempToken, env.JWT_SECRET) as { sub?: number; email?: string; scope?: string };
    } catch {
        await bumpFailure(env, ipKey);
        logAudit(env, ctx, null, 'LOGIN_2FA_FAILURE', { reason: 'Invalid temp token' }, ipAddress, userAgent);
        return jsonResponse({ message: 'Your verification session expired. Please sign in again.' }, 401);
    }

    if (decoded.scope !== '2fa' || typeof decoded.sub !== 'number') {
        await bumpFailure(env, ipKey);
        logAudit(env, ctx, null, 'LOGIN_2FA_FAILURE', { reason: 'Wrong token scope' }, ipAddress, userAgent);
        return jsonResponse({ message: 'Invalid verification session.' }, 401);
    }

    const userId = decoded.sub;
    const userKey = `rate_limit:2fa:user:${userId}`;
    if (await isRateLimited(env, userKey)) {
        logAudit(env, ctx, userId, 'LOGIN_2FA_FAILURE', { reason: 'User rate limited' }, ipAddress, userAgent);
        return jsonResponse({ message: 'Too many attempts. Try again later.' }, 429);
    }

    try {
        const user = await env.DB.prepare('SELECT id, email, encryption_salt FROM users WHERE id = ?')
            .bind(userId).first<{ id: number; email: string; encryption_salt: string }>();
        const row = await getTotpRow(env, userId);

        if (!user || row?.enabled !== 1 || !row.secret_enc) {
            await bumpFailure(env, ipKey);
            await bumpFailure(env, userKey);
            return jsonResponse({ message: 'Two-factor authentication is not set up.' }, 401);
        }

        const secret = await decryptSecret(env, row.secret_enc);
        let ok = verifyTotpToken(secret, user.email, code);
        let recoveryCodeUsed = false;
        if (!ok) {
            ok = await consumeRecoveryCode(env, userId, code);
            recoveryCodeUsed = ok;
        }

        if (!ok) {
            await bumpFailure(env, ipKey);
            await bumpFailure(env, userKey);
            logAudit(env, ctx, userId, 'LOGIN_2FA_FAILURE', { reason: 'Invalid code' }, ipAddress, userAgent);
            return jsonResponse({ message: 'Invalid code.' }, 401);
        }

        await clearFailures(env, ipKey);
        await clearFailures(env, userKey);

        const token = sign({ userId: user.id, email: user.email }, env.JWT_SECRET, { expiresIn: SESSION_TOKEN_TTL });
        const remainingRecoveryCodes = recoveryCodeUsed ? await countUnusedRecoveryCodes(env, userId) : undefined;
        logAudit(env, ctx, userId, 'LOGIN_SUCCESS', { via: recoveryCodeUsed ? 'recovery_code' : 'totp' }, ipAddress, userAgent);
        return jsonResponse({
            message: 'Login successful.',
            userId: user.id,
            email: user.email,
            encryptionSalt: user.encryption_salt,
            token,
            recoveryCodeUsed,
            remainingRecoveryCodes
        });
    } catch (error: any) {
        console.error('2FA login verification error:', error);
        logAudit(env, ctx, userId, 'LOGIN_2FA_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}

// Exported for unit testing of the pure helpers.
export const __testables = {
    normalizeRecoveryCode,
    hashRecoveryCode,
    generateRecoveryCodes,
    buildTotp,
    verifyTotpToken,
    totpUri,
    qrDataUri,
    encryptSecret,
    decryptSecret,
    RECOVERY_CODE_ALPHABET,
    RECOVERY_CODE_COUNT
};
