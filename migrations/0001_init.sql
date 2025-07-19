-- D1 Database Schema for Passflares

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,         -- Stores scrypt hash (salt.hash)
    encryption_salt TEXT NOT NULL,      -- Client-side encryption key derivation salt (for PBKDF2)
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Vaults Table
CREATE TABLE IF NOT EXISTS vaults (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    owner_id TEXT NOT NULL,             -- 'user_X' or 'org_Y'
    owner_type TEXT NOT NULL,           -- 'user' or 'organization'
    r2_object_key TEXT UNIQUE NOT NULL, -- Key for the R2 bucket object storing encrypted data
    current_key_version TEXT DEFAULT 'v1', -- To track master password changes / key re-encryptions
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Organizations Table
CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_by INTEGER NOT NULL,        -- User ID who created the organization
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
);

-- User-Organization Many-to-Many Relationship
CREATE TABLE IF NOT EXISTS user_organizations (
    user_id INTEGER NOT NULL,
    organization_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('member', 'admin')), -- 'member' or 'admin'
    joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, organization_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- Vault Access Controls (for sharing vaults with other users/orgs)
CREATE TABLE IF NOT EXISTS vault_access_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id INTEGER NOT NULL,
    entity_id TEXT NOT NULL,            -- 'user_X' or 'org_Y'
    entity_type TEXT NOT NULL,          -- 'user' or 'organization'
    permission_level TEXT NOT NULL CHECK(permission_level IN ('read', 'write', 'manage')), -- 'read', 'write', 'manage'
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (vault_id, entity_id), -- An entity can only have one permission level per vault
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
);

-- Audit Logs (for security monitoring)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,                    -- NULL for unauthenticated actions (e.g., failed login attempts)
    action TEXT NOT NULL,               -- e.g., 'LOGIN', 'REGISTER', 'VAULT_ACCESS', 'VAULT_CREATE', 'PASSWORD_CHANGE'
    payload TEXT NOT NULL,              -- JSON string with relevant details (e.g., { "success": true, "email": "user@example.com" })
    ip_address TEXT,
    user_agent TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
