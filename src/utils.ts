// src/utils.ts

// @noble/hashes 2.x requires the .js extension on submodule imports — see
// https://github.com/paulmillr/noble-hashes/releases/tag/2.0.1 . The runtime
// is unchanged; this is purely an ESM-resolution requirement.
import { scrypt, scryptAsync } from '@noble/hashes/scrypt.js';
import { randomBytes } from '@noble/hashes/utils.js';
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
        bytes.push(parseInt(hexString.substr(i, 2), 16));
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
