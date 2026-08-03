// src/types.ts

// Extend the Request object from itty-router to include custom properties
// that middleware will add (like `user`).
export interface CustomRequest extends Request {
    user?: {
        userId: number;
        email: string;
        iat: number; // issued at
        exp: number; // expiration
    };
    params?: {
        vaultId?: string;
        userId?: string;
        orgId?: string;
        memberUserId?: string;
    };
    query?: { // itty-router query params
        [key: string]: string | string[] | undefined;
    };
}

// Define the Cloudflare Worker Environment interface
export interface Env {
    DB: D1Database;
    VAULTS: R2Bucket;
    RATE_LIMIT: KVNamespace;
    // Provisioned here ahead of the code that uses it. A Durable Object
    // migration is an atomic control-plane operation that `wrangler versions
    // upload` cannot apply, so the namespace has to exist before the change
    // that depends on it can be previewed on a branch. Nothing reads this yet.
    RATE_LIMITER: DurableObjectNamespace<import('./rateLimiter.js').RateLimiter>;
    ASSETS: Fetcher;
    JWT_SECRET: string;
    TURNSTILE_KEY: string;
    TOTP_ENC_KEY: string; // encrypts TOTP secrets at rest (AES-GCM key material)
}

/**
 * 1 — legacy. The master password was POSTed to the worker and the vault key was
 *     PBKDF2(password, encryption_salt), both inputs known server-side. This is
 *     the model GHSA-pqm6-r3vj-mhvq describes; accounts are upgraded in place on
 *     next login and no new account is ever created at this version.
 * 2 — key hierarchy. The server receives only
 *     authSecret = HKDF(Argon2id(password, kdf_salt), "passflares:auth:v2")
 *     and stores scrypt(authSecret). It cannot derive any vault key.
 */
export type AuthVersion = 1 | 2;

export const AUTH_VERSION_LEGACY: AuthVersion = 1;
export const AUTH_VERSION_KEY_HIERARCHY: AuthVersion = 2;

/** Argon2id cost, stored per-user so it can be raised without breaking old accounts. */
export interface KdfParams {
    m: number;   // memory, KiB
    t: number;   // time (passes)
    p: number;   // parallelism
    len: number; // output bytes
}

// Interfaces for database entities (optional but good practice)
export interface User {
    id: number;
    email: string;
    password_hash: string;   // v1: scrypt(password). v2: scrypt(authSecret).
    password_salt: string;
    encryption_salt: string; // v1 PBKDF2 salt; retained while legacy_vaults_pending > 0, then ''
    auth_version: AuthVersion;
    kdf_salt: string | null;    // Argon2id salt (v2)
    kdf_params: string | null;  // JSON KdfParams (v2)
    legacy_vaults_pending: number;
    created_at: string;
}

/** Per-user asymmetric identity. The private key is only ever decrypted client-side. */
export interface UserKeys {
    user_id: number;
    public_key: string;      // P-256 ECDH SPKI, base64
    private_key_enc: string; // AES-256-GCM(kek, PKCS#8), "ivHex:ctHex"
    created_at: string;
    updated_at: string;
}

/**
 * A vault key wrapped to one member's public key. This is the primitive that
 * makes shared vaults work (#69) — access is granted by writing a row, without
 * the recipient being online and without touching vault ciphertext.
 */
export interface VaultKeyShare {
    vault_id: number;
    user_id: number;
    wrapped_key: string;      // AES-256-GCM(wrapKey, vaultKey), "ivHex:ctHex"
    ephemeral_pubkey: string; // sender's per-share P-256 SPKI, base64
    key_version: string;
    created_by: number | null;
    created_at: string;
}

export interface UserTotp {
    user_id: number;
    secret_enc: string | null;        // active secret (AES-GCM "v1:iv:ct"); null until first confirm
    pending_secret_enc: string | null; // in-flight enrollment/change
    enabled: number;                  // 0 | 1
    confirmed_at: string | null;
    created_at: string;
    updated_at: string;
}

export interface UserRecoveryCode {
    id: number;
    user_id: number;
    code_hash: string; // HMAC-SHA256(server pepper, normalized code)
    used_at: string | null;
    created_at: string;
}

export interface VaultMetadata {
    id: number;
    name: string;
    description: string | null;
    owner_id: string; // 'user_X' or 'org_Y'
    owner_type: 'user' | 'organization';
    r2_object_key: string;
    current_key_version: string; // e.g., 'v1'
    created_at: string;
    updated_at: string;
    // For JOIN results, may include permission_level
    permission_level?: 'read' | 'write' | 'manage';
}

export interface Organization {
    id: number;
    name: string;
    description: string | null;
    created_by: number; // userId
    created_at: string;
}

export type OrgRole = 'member' | 'admin' | 'super_admin';

export interface UserOrganization {
    user_id: number;
    organization_id: number;
    role: OrgRole;
    joined_at: string;
}

// Org roles that grant administrative privileges (creating org-owned vaults,
// managing members, deleting the org, etc.). The org creator is seeded as
// 'super_admin' (see handleCreateOrganization), so any admin gate must accept
// BOTH roles — checking 'admin' alone locks owners out of their own org.
export const ADMIN_ROLES: readonly OrgRole[] = ['admin', 'super_admin'];

export interface VaultAccessControl {
    id: number;
    vault_id: number;
    entity_id: string; // 'user_X' or 'org_Y'
    entity_type: 'user' | 'organization';
    permission_level: 'read' | 'write' | 'manage';
    created_at: string;
}

export interface AuditLogEntry {
    id: number;
    user_id: number | null; // Null for unauthenticated actions
    action: string;
    payload: string; // JSON string of details
    ip_address: string | null;
    user_agent: string | null;
    timestamp: string;
}

// For encrypted R2 data blob
export interface EncryptedVaultBlob {
    iv: string;         // Hex string of IV
    ciphertext: string; // Hex string of encrypted data
}

/**
 * R2 object key for a given vault key version.
 *
 * 'v1' maps to the bare key so every object written before the key hierarchy
 * landed stays reachable without a bulk R2 rename. Later versions get a suffix,
 * which is what makes re-encryption non-destructive: the new blob is written
 * beside the old one and only becomes live when the server flips
 * vaults.current_key_version (#70).
 */
export function versionedObjectKey(r2ObjectKey: string, keyVersion: string | null | undefined): string {
    return !keyVersion || keyVersion === 'v1' ? r2ObjectKey : `${r2ObjectKey}.${keyVersion}`;
}

/** Vault key versions the server will accept a write for. */
export const VALID_KEY_VERSIONS: readonly string[] = ['v1', 'v2'];

export type ThemePref   = 'light' | 'dark' | 'system';
export type DensityPref = 'compact' | 'comfortable' | 'spacious';
export type ShapePref   = 'sharp' | 'rounded' | 'pill';
export type AccentPref  = 'emerald' | 'blue' | 'purple' | 'orange';

export interface UserPreferences {
    user_id: number;
    theme: ThemePref;
    density: DensityPref;
    shape: ShapePref;
    accent: AccentPref;
    updated_at: string;
}

export const DEFAULT_PREFERENCES: Omit<UserPreferences, 'user_id' | 'updated_at'> = {
    theme: 'system',
    density: 'comfortable',
    shape: 'rounded',
    accent: 'emerald'
};

export const THEME_VALUES:   ReadonlyArray<ThemePref>   = ['light', 'dark', 'system'];
export const DENSITY_VALUES: ReadonlyArray<DensityPref> = ['compact', 'comfortable', 'spacious'];
export const SHAPE_VALUES:   ReadonlyArray<ShapePref>   = ['sharp', 'rounded', 'pill'];
export const ACCENT_VALUES:  ReadonlyArray<AccentPref>  = ['emerald', 'blue', 'purple', 'orange'];
