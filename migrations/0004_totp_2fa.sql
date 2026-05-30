-- TOTP two-factor authentication + single-use recovery codes.
-- Two new tables keyed by user_id (FK cascade on user delete), so no ALTER of
-- the users table is needed.

CREATE TABLE IF NOT EXISTS user_totp (
    user_id            INTEGER PRIMARY KEY,
    secret_enc         TEXT,            -- active secret, AES-GCM "v1:ivHex:ctHex"; NULL until first confirm
    pending_secret_enc TEXT,            -- in-flight enrollment/change; NULL when none
    enabled            INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    confirmed_at       TEXT,
    created_at         TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at         TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    code_hash  TEXT NOT NULL,           -- HMAC-SHA256(server pepper, normalized code), hex
    used_at    TEXT,                    -- NULL until consumed (one-time use)
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON user_recovery_codes(user_id);
