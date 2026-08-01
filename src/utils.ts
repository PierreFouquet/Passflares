// src/utils.ts

// @noble/hashes 2.x requires the .js extension on submodule imports — see
// https://github.com/paulmillr/noble-hashes/releases/tag/2.0.1 . The runtime
// is unchanged; this is purely an ESM-resolution requirement.
import { scrypt, scryptAsync } from '@noble/hashes/scrypt.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Env } from './types.js'; // Ensure correct path and .js extension

export const KDF_SALT_LENGTH_BYTES = 16;
export const KDF_COST_N = 32768;  // Increased from 16384
export const KDF_COST_R = 12;     // Increased from 8
export const KDF_COST_P = 1;
export const KDF_KEY_LENGTH_BYTES = 32;

/**
 * Derives a strong hash from a password using scrypt.
 * This function is CPU-bound and asynchronous.
 * @param password The plaintext password.
 * @param saltHex Hex string of the salt. If null, a new salt will be generated.
 * @returns {Promise<{hash: string, salt: string}>} The derived hash and the salt used, both as hex strings.
 */
export async function deriveScryptHash(password: string, saltHex: string | null = null): Promise<{ hash: string; salt: string }> {
    const salt = saltHex ? hexStringToUint8Array(saltHex) : randomBytes(KDF_SALT_LENGTH_BYTES);
    const passwordBytes = new TextEncoder().encode(password);

    // Using scryptAsync for non-blocking operation
    const hashBytes = await scryptAsync(
        passwordBytes,
        salt,
        {
            N: KDF_COST_N,
            r: KDF_COST_R,
            p: KDF_COST_P,
            dkLen: KDF_KEY_LENGTH_BYTES
        }
    );

    return {
        hash: uint8ArrayToHexString(hashBytes),
        salt: uint8ArrayToHexString(salt)
    };
}

/**
 * Constant-time comparison of two hex-encoded digests.
 *
 * `===` on hash strings short-circuits at the first differing byte, leaking the
 * length of the matching prefix through timing (GHSA-jrh6-9qp8-rfgf). Exploiting
 * it here would require inverting scrypt, so it was never a practical login
 * bypass — but constant-time comparison is table stakes for an auth system and
 * removes the need to re-reason about reachability after every future refactor.
 *
 * Returns false on malformed input rather than throwing, so callers can treat a
 * corrupt stored hash as "no match" instead of a 500.
 *
 * The length check ahead of the loop is not a leak: both operands are
 * fixed-width scrypt outputs, so a length mismatch means a malformed stored
 * value, not a partially-correct guess. Workers has no `crypto.timingSafeEqual`
 * and @noble/hashes 2.x no longer exports `equalBytes`, so the accumulator is
 * written out here — it must stay branch-free over the full length.
 */
const HEX_RE = /^[0-9a-fA-F]+$/;

export function timingSafeEqualHex(a: string, b: string): boolean {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length || a.length === 0 || a.length % 2 !== 0) return false;
    // Validate before decoding: hexStringToUint8Array turns a non-hex pair into
    // NaN, which Uint8Array silently stores as 0 — so without this, two equally
    // corrupt values would compare equal.
    if (!HEX_RE.test(a) || !HEX_RE.test(b)) return false;

    const left = hexStringToUint8Array(a);
    const right = hexStringToUint8Array(b);

    let diff = 0;
    for (let i = 0; i < left.length; i++) {
        diff |= left[i] ^ right[i];
    }
    return diff === 0;
}

/**
 * Normalises an email for storage and lookup.
 *
 * SQLite's UNIQUE is case-sensitive, so without this `Foo@example.com` and
 * `foo@example.com` are two separate accounts with two separate vault sets.
 */
export function normalizeEmail(email: unknown): string {
    return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

// Deliberately conservative: one @, no whitespace, a dot-bearing domain. The
// only prior validation was the browser's `type="email"`, which is bypassed by
// calling the API directly.
const EMAIL_RE = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

export function isValidEmail(email: string): boolean {
    return email.length <= 254 && EMAIL_RE.test(email);
}

/**
 * Parses a path segment as a positive integer ID.
 *
 * Deliberately stricter than either built-in: `parseInt('12abc', 10)` returns
 * 12, and `Number('0x10')` returns 16 — both surprising for an ID parser, and
 * both mean two different URLs address the same row. Only a plain run of
 * decimal digits is accepted, so `/vaults/0x10` is a 400 rather than vault 16.
 */
const DECIMAL_ID_RE = /^[0-9]+$/;

export function parseId(value: string | undefined | null): number | null {
    if (typeof value !== 'string' || !DECIMAL_ID_RE.test(value)) return null;
    const n = Number(value);
    return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/** Parses a KV-stored counter, treating anything unparseable as zero. */
export function parseCounter(value: string | null | undefined): number {
    const n = parseInt(value ?? '', 10);
    return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Deterministic, non-secret-leaking stand-in KDF salt for an unknown account.
 *
 * /api/auth/params has to answer before the caller has authenticated, so
 * returning "no such user" would make it an account-existence oracle. Instead
 * unknown emails get a salt derived from a server secret — stable across calls
 * (so retries look consistent), unpredictable to the caller, and indistinguishable
 * from a real one.
 */
export function decoyKdfSalt(email: string, secret: string): string {
    const mac = hmac(sha256, new TextEncoder().encode(secret), new TextEncoder().encode(`authparams:${email}`));
    return uint8ArrayToHexString(mac.slice(0, KDF_SALT_LENGTH_BYTES));
}

/**
 * Converts a Uint8Array to a hexadecimal string.
 * @param uint8array The Uint8Array to convert.
 * @returns The hexadecimal string.
 */
export function uint8ArrayToHexString(uint8array: Uint8Array): string {
    return Array.from(uint8array)
        .map((b: number) => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Converts a hexadecimal string to a Uint8Array.
 * @param hexString The hexadecimal string to convert.
 * @returns The Uint8Array.
 * @throws {Error} If the hex string has an odd number of characters.
 */
export function hexStringToUint8Array(hexString: string): Uint8Array {
    if (hexString.length % 2 !== 0) {
        throw new Error("Hex string must have an even number of characters.");
    }
    const bytes: number[] = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.slice(i, i + 2), 16));
    }
    return new Uint8Array(bytes);
}

/**
 * Helper to create a JSON response.
 * @param body The response body object.
 * @param status HTTP status code.
 * @returns A Response object.
 */
export function jsonResponse(body: Record<string, any>, status: number = 200): Response {
    return new Response(JSON.stringify(body), {
        headers: { 'Content-Type': 'application/json' },
        status: status
    });
}

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

/**
 * Verifies a Cloudflare Turnstile token against the siteverify endpoint.
 * Returns true only when Cloudflare confirms `success: true`. Missing tokens,
 * network errors, and unexpected responses all resolve to false so the caller
 * can fail closed.
 */
export async function verifyTurnstile(
    token: string | null | undefined,
    secret: string,
    ipAddress: string | null = null
): Promise<boolean> {
    if (!token || !secret) return false;

    const formData = new FormData();
    formData.append('secret', secret);
    formData.append('response', token);
    if (ipAddress) formData.append('remoteip', ipAddress);

    try {
        const result = await fetch(TURNSTILE_VERIFY_URL, {
            method: 'POST',
            body: formData
        });
        if (!result.ok) return false;
        const data = await result.json() as { success?: boolean };
        return data.success === true;
    } catch {
        return false;
    }
}
