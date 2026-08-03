-- 0006_audit_log_indexes.sql
--
-- Indexes for the audit log's read and retention paths (#73, and the audit
-- subset of #72).
--
-- Until now `audit_logs` had no index at all, while receiving a row on
-- essentially every authenticated request. Both new access patterns would
-- otherwise be full table scans on the largest table in the database:
--
--   * the nightly retention sweep      -> WHERE timestamp < ? ORDER BY timestamp
--   * GET /api/users/me/audit-log      -> WHERE user_id = ? ORDER BY timestamp DESC
--
-- Purely additive; safe to apply to the live database while it serves traffic.

-- Retention sweep. Also serves any bare time-range query.
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);

-- Per-account read. The composite order matters: user_id first makes this a
-- range scan over one account's rows already in timestamp order, so the
-- ORDER BY ... DESC LIMIT is satisfied by the index rather than a sort.
CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_logs(user_id, timestamp);

-- The recovery-code redemption in src/totp.ts is now a single guarded UPDATE
-- matching on (user_id, code_hash) — GHSA-q9vh-jccv-9p23. 0004 indexed
-- user_id alone, which leaves SQLite filtering every code the account owns on
-- each 2FA verification.
CREATE INDEX IF NOT EXISTS idx_recovery_codes_lookup
    ON user_recovery_codes(user_id, code_hash);
