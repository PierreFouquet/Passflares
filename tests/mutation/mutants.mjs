// Curated mutants for the falsifiability gate (#83).
//
// Each entry breaks one security-critical behaviour. `find` must match exactly
// once in `file`, so a refactor that moves the code fails loudly rather than
// silently testing nothing.
//
// SURVIVED = the suite stayed green while the behaviour was broken. That is
// either a missing test or an equivalent mutant; triage before "fixing".

export const mutants = [
    // ── middleware: resolveVaultAccess scoping ─────────────────────
    {
        id: 'mw-owner-any-vault',
        file: 'src/middleware.ts',
        desc: 'direct-owner query stops scoping to the requested vault',
        find: "\"SELECT id FROM vaults WHERE id = ? AND owner_id = ? AND owner_type = 'user'\"",
        replace: "\"SELECT id FROM vaults WHERE owner_id = ? AND owner_type = 'user'\""
    },
    {
        id: 'mw-acl-any-user',
        file: 'src/middleware.ts',
        desc: 'user ACL lookup stops scoping to the requesting user',
        find: "WHERE vault_id = ? AND entity_id = ? AND entity_type = 'user'",
        replace: "WHERE vault_id = ? AND entity_type = 'user' AND ? IS NOT NULL"
    },
    {
        id: 'mw-org-any-member',
        file: 'src/middleware.ts',
        desc: 'org ACL lookup stops scoping to the requesting user',
        find: 'WHERE vac.vault_id = ? AND uo.user_id = ?',
        replace: 'WHERE vac.vault_id = ? AND ? IS NOT NULL'
    },
    {
        id: 'mw-no-access-grants-manage',
        file: 'src/middleware.ts',
        desc: 'a user with no grant at all resolves to manage',
        find: 'return orgAccess ? orgAccess.permission_level : null;',
        replace: "return orgAccess ? orgAccess.permission_level : 'manage';"
    },

    // ── middleware: permission ranking ─────────────────────────────
    {
        id: 'mw-perm-always-ok',
        file: 'src/middleware.ts',
        desc: 'every permission level satisfies every requirement',
        find: 'return PERMISSION_RANK[has] >= PERMISSION_RANK[required];',
        replace: 'return true;'
    },
    {
        id: 'mw-perm-inverted',
        file: 'src/middleware.ts',
        desc: 'read satisfies write (ranking comparison inverted)',
        find: 'return PERMISSION_RANK[has] >= PERMISSION_RANK[required];',
        replace: 'return PERMISSION_RANK[has] <= PERMISSION_RANK[required];'
    },

    // ── middleware: authentication ─────────────────────────────────
    {
        id: 'mw-2fa-token-accepted',
        file: 'src/middleware.ts',
        desc: 'the short-lived 2FA step-up token authorizes protected routes',
        find: "if (decoded.scope === '2fa' || typeof decoded.userId !== 'number') {",
        replace: 'if (false) {'
    },
    {
        id: 'mw-missing-user-context',
        file: 'src/middleware.ts',
        desc: 'a request with no user context passes the vault permission check',
        find: 'if (!vaultIdParam || !user || !user.userId) {',
        replace: 'if (!vaultIdParam) {'
    },

    // ── auth: credential verification ──────────────────────────────
    {
        id: 'auth-login-any-password',
        file: 'src/auth.ts',
        desc: 'login stops verifying the password hash',
        find: 'if (!timingSafeEqualHex(verifiedHash, user.password_hash)) {\n            await bumpFailures();',
        replace: 'if (false) {\n            await bumpFailures();'
    },
    {
        id: 'auth-delete-account-any-password',
        file: 'src/auth.ts',
        desc: 'account deletion stops verifying the password',
        find: 'if (!timingSafeEqualHex(verifiedHash, user.password_hash)) {\n            await recordFailure(env, subjects);',
        replace: 'if (false) {\n            await recordFailure(env, subjects);'
    },
    {
        id: 'auth-change-password-unverified',
        file: 'src/auth.ts',
        desc: 'changing the master password stops verifying the current one',
        find: 'if (!timingSafeEqualHex(verifiedOldHash, user.password_hash)) {',
        replace: 'if (false) {'
    },
    {
        id: 'utils-timing-equal-always',
        file: 'src/utils.ts',
        desc: 'timingSafeEqualHex returns true for any two values',
        find: 'export function timingSafeEqualHex(a: string, b: string): boolean {',
        replace: 'export function timingSafeEqualHex(a: string, b: string): boolean {\n    if (1) return true;'
    },

    // ── recovery codes: single use (GHSA-q9vh-jccv-9p23) ───────────
    {
        id: 'totp-recovery-reusable',
        file: 'src/totp.ts',
        desc: 'a recovery code can be redeemed more than once',
        find: 'return (result.meta?.changes ?? 0) === 1;',
        replace: 'return true;'
    },
    {
        id: 'totp-recovery-unguarded',
        file: 'src/totp.ts',
        desc: 'the used_at guard leaves the UPDATE, reopening the race',
        find: 'WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`',
        replace: 'WHERE user_id = ? AND code_hash = ?`'
    },
    {
        id: 'totp-recovery-any-user',
        file: 'src/totp.ts',
        desc: 'a recovery code can be redeemed against another account',
        find: 'WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`',
        replace: 'WHERE code_hash = ? AND used_at IS NULL AND ? IS NOT NULL`'
    },
    {
        id: 'totp-code-never-checked',
        file: 'src/totp.ts',
        desc: 'any TOTP code validates',
        find: "return buildTotp(secretBase32, label).validate({ token: normalized, window: 1 }) !== null;",
        replace: 'return true;'
    },

    // ── rate limiting (GHSA-vp89-22wm-gjr8) ────────────────────────
    {
        id: 'rl-never-locks-out',
        file: 'src/rateLimiter.ts',
        desc: 'the lockout is never applied, however many failures',
        find: 'if (failures < policy.threshold) return 0;',
        replace: 'if (1) return 0;'
    },
    {
        id: 'rl-no-backoff-growth',
        file: 'src/rateLimiter.ts',
        desc: 'the lockout stops growing with repeated failures',
        find: 'return Math.min(policy.baseLockoutMs * 2 ** steps, MAX_LOCKOUT_MS);',
        replace: 'return policy.baseLockoutMs;'
    },
    {
        id: 'rl-decay-ignores-lockout',
        file: 'src/rateLimiter.ts',
        desc: 'an active lockout forgives itself once DECAY_MS elapses',
        find: 'if (now >= stored.lockedUntil && now - stored.updatedAt > DECAY_MS) {',
        replace: 'if (now - stored.updatedAt > DECAY_MS) {'
    },

    // ── audit log (#73) ────────────────────────────────────────────
    {
        id: 'audit-write-not-registered',
        file: 'src/auditLog.ts',
        desc: 'the audit write is never registered with ctx.waitUntil',
        find: 'ctx.waitUntil(write);',
        replace: 'void write;'
    },
    {
        id: 'audit-read-any-user',
        file: 'src/auditLog.ts',
        desc: 'the audit log read stops scoping to the calling account',
        find: '`SELECT action, payload, ip_address, user_agent, timestamp FROM audit_logs\n             WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?`',
        replace: '`SELECT action, payload, ip_address, user_agent, timestamp FROM audit_logs\n             WHERE ? IS NOT NULL ORDER BY timestamp DESC LIMIT ?`'
    },
    {
        id: 'audit-page-cap-removed',
        file: 'src/auditLog.ts',
        desc: 'the audit page-size ceiling stops being applied',
        find: 'const capped = Math.min(Math.max(limit, 1), AUDIT_PAGE_MAX);',
        replace: 'const capped = limit;'
    },
    {
        id: 'audit-retention-deletes-all',
        file: 'src/auditLog.ts',
        desc: 'the retention sweep deletes rows inside the retention window',
        find: 'const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();',
        replace: 'const cutoff = new Date(Date.now()).toISOString();'
    },

    // ── organisations: last-owner guard ────────────────────────────
    {
        id: 'org-demote-last-owner',
        file: 'src/organizations.ts',
        desc: 'the last owner can be demoted, stranding the organisation',
        // Unreachable: the caller must be super_admin and the target a
        // *different* super_admin, so COUNT is always >= 2. The real protection
        // is the earlier self-demotion 403, which authz-real-db.test.ts covers.
        equivalent: 'guard is dead code — see #83',
        find: 'if ((superAdminCount?.count ?? 0) <= 1) {\n                return jsonResponse({ message: "Forbidden: Cannot demote the last owner." }, 409);',
        replace: 'if (false) {\n                return jsonResponse({ message: "Forbidden: Cannot demote the last owner." }, 409);'
    },
    {
        id: 'org-remove-last-owner',
        file: 'src/organizations.ts',
        desc: 'the last owner can be removed, stranding the organisation',
        // Same shape: only a super_admin reaches it, and removing another
        // super_admin implies COUNT >= 2.
        equivalent: 'guard is dead code — see #83',
        find: 'if ((superAdminCount?.count ?? 0) <= 1) {\n                return jsonResponse({ message: "Forbidden: Cannot remove the last owner." }, 409);',
        replace: 'if (false) {\n                return jsonResponse({ message: "Forbidden: Cannot remove the last owner." }, 409);'
    },
    {
        id: 'org-any-member-removes',
        file: 'src/organizations.ts',
        desc: 'a plain member can remove other members',
        find: 'if (!callerRole || !ADMIN_ROLES.includes(callerRole.role as any)) {',
        replace: 'if (!callerRole) {'
    },
    {
        id: 'org-admin-removes-owner',
        file: 'src/organizations.ts',
        desc: 'an admin can remove an owner',
        find: "if (targetRole.role === 'super_admin' && callerRole.role !== 'super_admin') {",
        replace: 'if (false) {'
    },

    // ── vaults ─────────────────────────────────────────────────────
    {
        id: 'vaults-stage-no-write-access',
        file: 'src/vaults.ts',
        desc: 'staging a re-encrypted blob skips the write-access check',
        find: 'const access = await resolveVaultAccess(env, user.userId, vaultId);',
        replace: "const access = 'manage' as any;"
    },
    {
        id: 'vaults-any-key-version',
        file: 'src/vaults.ts',
        desc: 'an arbitrary key version is accepted on write',
        find: 'if (keyVersion !== undefined && !VALID_KEY_VERSIONS.includes(keyVersion)) {\n        logAudit(env, ctx, user.userId, \'VAULT_UPLOAD_FAILURE\'',
        replace: 'if (false) {\n        logAudit(env, ctx, user.userId, \'VAULT_UPLOAD_FAILURE\''
    },

    // ── input validation ───────────────────────────────────────────
    {
        id: 'utils-parseid-accepts-junk',
        file: 'src/utils.ts',
        desc: 'parseId stops rejecting non-numeric ids',
        find: 'export function parseId(value: string | undefined | null): number | null {',
        replace: 'export function parseId(value: string | undefined | null): number | null {\n    if (1) return Number(value) || 1;'
    },
    {
        id: 'utils-email-accepts-anything',
        file: 'src/utils.ts',
        desc: 'isValidEmail accepts any string',
        find: 'export function isValidEmail(email: string): boolean {',
        replace: 'export function isValidEmail(email: string): boolean {\n    if (1) return true;'
    },
    {
        id: 'prefs-accepts-any-value',
        file: 'src/preferences.ts',
        desc: 'preference values stop being validated against their enums',
        find: 'function isOneOf<T extends string>(value: unknown, allowed: ReadonlyArray<T>): value is T {',
        replace: 'function isOneOf<T extends string>(value: unknown, allowed: ReadonlyArray<T>): value is T {\n    if (1) return true;'
    }
];
