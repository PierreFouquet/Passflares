-- Per-user UI preferences synced across devices.
-- Loaded after login; written from the Settings page.

CREATE TABLE IF NOT EXISTS user_preferences (
    user_id    INTEGER PRIMARY KEY,
    theme      TEXT NOT NULL DEFAULT 'system'      CHECK(theme IN ('light', 'dark', 'system')),
    density    TEXT NOT NULL DEFAULT 'comfortable' CHECK(density IN ('compact', 'comfortable', 'spacious')),
    shape      TEXT NOT NULL DEFAULT 'rounded'     CHECK(shape IN ('sharp', 'rounded', 'pill')),
    accent     TEXT NOT NULL DEFAULT 'emerald'     CHECK(accent IN ('emerald', 'blue', 'purple', 'orange')),
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
