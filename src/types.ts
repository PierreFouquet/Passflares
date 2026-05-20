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
    ASSETS: Fetcher;
    JWT_SECRET: string;
    TURNSTILE_KEY: string;
}

// Interfaces for database entities (optional but good practice)
export interface User {
    id: number;
    email: string;
    password_hash: string;
    password_salt: string;
    encryption_salt: string; // client-side encryption salt
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

export interface UserOrganization {
    user_id: number;
    organization_id: number;
    role: 'member' | 'admin' | 'super_admin';
    joined_at: string;
}

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
