-- Zero-knowledge key hierarchy (auth_version 2).
--
-- Resolves GHSA-pqm6-r3vj-mhvq, #69 and #70. See README's "Security model"
-- section for the design; the short version:
--
--   masterKey  = Argon2id(password, kdf_salt, kdf_params)      -- browser only
--   authSecret = HKDF(masterKey, "passflares:auth:v2")         -- sent to server
--   kek        = HKDF(masterKey, "passflares:kek:v2")          -- browser only
--
-- users.password_hash becomes scrypt(authSecret) instead of scrypt(password),
-- so the server never receives anything that can derive a vault key.
--
-- ADDITIVE ONLY. Every v1 account keeps working unchanged until its owner next
-- signs in, at which point the client performs a one-shot in-place upgrade. No
-- column is dropped here — the legacy columns are retired in a later migration,
-- after the auth_version = 1 population reaches zero.

-- 1 = legacy (password to server, PBKDF2 vault key). 2 = key hierarchy.
ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1;

-- Argon2id inputs for deriving masterKey. Non-secret; served by /api/auth/params
-- before the user has authenticated. NULL while auth_version = 1.
ALTER TABLE users ADD COLUMN kdf_salt TEXT;
ALTER TABLE users ADD COLUMN kdf_params TEXT;   -- JSON: {"m":47104,"t":1,"p":1,"len":32}

-- Count of the user's organisation-owned vaults still holding v1 ciphertext.
-- Those can only be re-keyed by the member who created them (nobody else can
-- decrypt them — that is #69), so they are migrated lazily on next open rather
-- than during the login upgrade. users.encryption_salt must be retained until
-- this reaches 0, because the legacy PBKDF2 key derivation needs it.
ALTER TABLE users ADD COLUMN legacy_vaults_pending INTEGER NOT NULL DEFAULT 0;

-- Per-user asymmetric identity. The public key is readable by anyone who shares
-- an organisation with the user (needed to wrap vault keys for them); the
-- private key is only ever decrypted in the owner's browser.
CREATE TABLE IF NOT EXISTS user_keys (
    user_id         INTEGER PRIMARY KEY,
    public_key      TEXT NOT NULL,      -- P-256 ECDH public key, SPKI, base64
    private_key_enc TEXT NOT NULL,      -- AES-256-GCM(kek, PKCS#8), "ivHex:ctHex"
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- One row per (vault, member) granting that member the vault's symmetric key.
-- This is the primitive #69 was missing: a vault key wrapped to a recipient's
-- public key via ECIES, so access can be granted without either party being
-- online and without anyone re-encrypting the vault contents.
--
-- Revoking access deletes the row AND requires rotating the vault key — a
-- removed member may have cached the old one.
CREATE TABLE IF NOT EXISTS vault_key_shares (
    vault_id         INTEGER NOT NULL,
    user_id          INTEGER NOT NULL,
    wrapped_key      TEXT NOT NULL,     -- AES-256-GCM(wrapKey, vaultKey), "ivHex:ctHex"
    ephemeral_pubkey TEXT NOT NULL,     -- sender's per-share P-256 public key, SPKI, base64
    key_version      TEXT NOT NULL DEFAULT 'v2',
    created_by       INTEGER,
    created_at       TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, user_id),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE
);

-- "Which vaults can I open?" is the hot path at login.
CREATE INDEX IF NOT EXISTS idx_vault_key_shares_user ON vault_key_shares(user_id);

-- Reverse lookup for re-wrap on member removal / key rotation.
CREATE INDEX IF NOT EXISTS idx_vault_key_shares_vault ON vault_key_shares(vault_id);
