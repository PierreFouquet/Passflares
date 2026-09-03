// Curated mutants for the falsifiability gate (#83).
//
// Each entry breaks one security-critical behaviour. `find` must match exactly
// once in `file`, so a refactor that moves the code fails loudly rather than
// silently testing nothing.
//
// SURVIVED = the suite stayed green while the behaviour was broken. That is
// either a missing test or an equivalent mutant; triage before "fixing".
//
// `suite` names the test directory that is supposed to notice the mutant, and
// defaults to DEFAULT_SUITE. Backend mutants are judged by tests/backend;
// browser mutants over public/js/ are judged by tests/frontend (#89 §1).

export const DEFAULT_SUITE = 'tests/backend';

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

    // ── organisations: keeping an owner ────────────────────────────
    //
    // These replace two mutants that were marked `equivalent` because the
    // `<= 1` last-owner guards they broke were unreachable. Those guards are
    // now deleted (#89), and what remains is the protection that was doing the
    // work all along: an owner cannot demote or remove *themselves*, and only
    // an owner may act on another owner. Dead defence-in-depth swapped for a
    // live, falsifiable assertion.
    {
        id: 'org-self-demote-allowed',
        file: 'src/organizations.ts',
        desc: 'an owner can demote themselves, leaving the organisation unowned',
        find: '    if (user.userId === targetUserId)\n        return jsonResponse({ message: "Forbidden: Cannot change your own role." }, 403);',
        replace: '    if (false)\n        return jsonResponse({ message: "Forbidden: Cannot change your own role." }, 403);'
    },
    {
        id: 'org-self-remove-allowed',
        file: 'src/organizations.ts',
        desc: 'an owner can remove themselves, leaving the organisation unowned',
        find: '    if (user.userId === targetUserId)\n        return jsonResponse({ message: "Forbidden: Cannot remove yourself from the organization." }, 403);',
        replace: '    if (false)\n        return jsonResponse({ message: "Forbidden: Cannot remove yourself from the organization." }, 403);'
    },
    {
        id: 'org-admin-demotes-owner',
        file: 'src/organizations.ts',
        desc: 'a mere admin can change roles, so an admin can demote an owner',
        // Anchored on the audit reason, because the bare role check appears
        // again in handleDeleteOrganization and an ambiguous pattern is
        // reported stale rather than silently mutating the wrong one.
        find: "        if (!callerRole || callerRole.role !== 'super_admin') {\n            logAudit(env, ctx, user.userId, 'ORG_UPDATE_ROLE_FAILURE'",
        replace: "        if (false) {\n            logAudit(env, ctx, user.userId, 'ORG_UPDATE_ROLE_FAILURE'"
    },
    {
        id: 'org-any-member-deletes-org',
        file: 'src/organizations.ts',
        desc: 'a plain member can delete the whole organisation',
        find: "        if (!callerRole || callerRole.role !== 'super_admin') {\n            logAudit(env, ctx, user.userId, 'ORG_DELETE_FAILURE'",
        replace: "        if (false) {\n            logAudit(env, ctx, user.userId, 'ORG_DELETE_FAILURE'"
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
    },

    // ── bot protection ─────────────────────────────────────────────
    // Both of these survived until the Stryker pilot pointed at them (#89 §2).
    // The suite asserted only what verifyTurnstile *returned*, never what it
    // sent or why it said no, so the request could be malformed and the
    // non-2xx test was green whether or not the guard it named existed.
    {
        id: 'turnstile-secret-blanked',
        file: 'src/utils.ts',
        desc: 'the Turnstile secret is replaced with an empty string on the wire',
        find: "    formData.append('secret', secret);",
        replace: "    formData.append('secret', '');"
    },
    {
        id: 'turnstile-ignores-http-status',
        file: 'src/utils.ts',
        desc: 'a non-2xx from siteverify is parsed as if it were a verdict',
        find: '        if (!result.ok) return false;',
        replace: '        if (false) return false;'
    },

    // ═══════════════════════════════════════════════════════════════
    //  public/js/ — the browser half (#89 §1)
    //
    //  Judged by tests/frontend. This is where the zero-knowledge
    //  guarantee actually lives: mutating src/ proves nothing about
    //  whether the browser still refuses to send the master password,
    //  so a vacuous test here hides more than a vacuous test in a
    //  handler.
    // ═══════════════════════════════════════════════════════════════

    // ── what goes on the wire ──────────────────────────────────────
    {
        id: 'fe-login-sends-password',
        file: 'public/js/auth-flow.js',
        suite: 'tests/frontend',
        desc: 'sign-in puts the master password in the login body',
        find: 'const response = await loginUser(email, { authSecret }, turnstileToken);',
        replace: 'const response = await loginUser(email, { authSecret, masterPassword: password }, turnstileToken);'
    },
    {
        id: 'fe-register-sends-password',
        file: 'public/js/auth-flow.js',
        suite: 'tests/frontend',
        desc: 'enrolment sends the master password as the auth verifier',
        // Sending it *as authSecret* rather than as an extra field, because an
        // extra field is inert: api.js's registerUser destructures a fixed list
        // of names, so anything else the caller passes is dropped before the
        // body is built. That allow-list is a real control and this mutant
        // would be equivalent without it — noted here so nobody "fixes" the
        // survivor by weakening the signature to a spread.
        find: 'await registerUser({ email, authSecret, kdfSalt, kdfParams, publicKey, privateKeyEnc, turnstileToken });',
        replace: 'await registerUser({ email, authSecret: password, kdfSalt, kdfParams, publicKey, privateKeyEnc, turnstileToken });'
    },
    {
        id: 'fe-rotate-sends-new-password',
        file: 'public/js/auth-flow.js',
        suite: 'tests/frontend',
        desc: 'password rotation puts the NEW master password in the update body',
        // Deliberately the new password, not the old one. An invariant that
        // only looks for the password the account already had would miss the
        // one being set — and that is the value an attacker wants.
        find: '    await updateMasterPassword(userId, {\n        oldAuthSecret,',
        replace: '    await updateMasterPassword(userId, {\n        masterPassword: newPassword,\n        oldAuthSecret,'
    },
    {
        id: 'fe-rotate-accepts-wrong-password',
        file: 'public/js/auth-flow.js',
        suite: 'tests/frontend',
        desc: 'a wrong current password no longer stops the rotation',
        find: "        .catch(() => { throw new Error('Current master password is incorrect.'); });",
        replace: '        .catch(() => privateKeyEnc);'
    },

    // ── the legacy upgrade's non-destructive ordering (#70) ────────
    {
        id: 'fe-upgrade-overwrites-live-blob',
        file: 'public/js/auth-flow.js',
        suite: 'tests/frontend',
        desc: 're-encrypted vaults overwrite the live blob instead of staging',
        find: "            await saveEncryptedVaultData(vault.id, reEncrypted, 'v2');",
        replace: '            await saveEncryptedVaultData(vault.id, reEncrypted);'
    },
    {
        id: 'fe-upgrade-commits-after-failure',
        file: 'public/js/auth-flow.js',
        suite: 'tests/frontend',
        desc: 'the upgrade commits even though a vault could not be re-encrypted',
        find: '    if (failed.length > 0) {',
        replace: '    if (false) {'
    },
    {
        id: 'fe-upgrade-rekeys-org-vaults',
        file: 'public/js/auth-flow.js',
        suite: 'tests/frontend',
        desc: 'the upgrade re-keys organisation vaults, locking out every other member',
        find: "    const ownVaults = allVaults.filter(v => v.owner_type === 'user' && v.permission_level === 'manage');",
        replace: '    const ownVaults = allVaults;'
    },

    // ── the key hierarchy's domain separation ──────────────────────
    {
        id: 'fe-kek-from-auth-info',
        file: 'public/js/keys.js',
        suite: 'tests/frontend',
        desc: 'the KEK is derived with the auth info string, so the server can compute it',
        // The whole point of two HKDF labels. Collapse them and authSecret —
        // which the server stores — reproduces the key that unwraps the
        // private key. This is GHSA-pqm6-r3vj-mhvq reopened.
        find: '    const raw = await hkdf(masterKey, HKDF_INFO_KEK);',
        replace: '    const raw = await hkdf(masterKey, HKDF_INFO_AUTH);'
    },
    {
        id: 'fe-authsecret-is-master-key',
        file: 'public/js/keys.js',
        suite: 'tests/frontend',
        desc: 'the raw master key is sent to the server instead of an HKDF branch of it',
        find: '    return uint8ArrayToHexString(await hkdf(masterKey, HKDF_INFO_AUTH));',
        replace: '    return uint8ArrayToHexString(masterKey);'
    },
    {
        id: 'fe-share-not-vault-bound',
        file: 'public/js/keys.js',
        suite: 'tests/frontend',
        desc: 'the share wrap key stops being bound to the vault id, so a row replays onto another vault',
        find: '    const wrapBytes = await hkdf(shared, HKDF_INFO_VAULT_SHARE, TEXT.encode(String(vaultId)));',
        replace: '    const wrapBytes = await hkdf(shared, HKDF_INFO_VAULT_SHARE);'
    },
    {
        id: 'fe-private-key-extractable',
        file: 'public/js/keys.js',
        suite: 'tests/frontend',
        desc: 'the unwrapped private key is imported as extractable',
        // Extractable means any XSS that reaches state.js can exportKey() the
        // identity that opens every vault share, rather than being limited to
        // whatever it can do while the tab is open.
        find: "    const key = await crypto.subtle.importKey('pkcs8', pkcs8, ECDH_PARAMS, false, ['deriveBits']);",
        replace: "    const key = await crypto.subtle.importKey('pkcs8', pkcs8, ECDH_PARAMS, true, ['deriveBits']);"
    },

    // ── AES-GCM misuse ─────────────────────────────────────────────
    {
        id: 'fe-vault-iv-fixed',
        file: 'public/js/crypto.js',
        suite: 'tests/frontend',
        desc: 'vault entries are sealed with an all-zero IV',
        // GCM IV reuse under one key is not a weakening, it is a break: two
        // ciphertexts under the same (key, IV) leak their XOR and hand over the
        // authentication subkey.
        find: '    const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));',
        replace: '    const iv = new Uint8Array(AES_IV_LENGTH);'
    },
    {
        id: 'fe-keyblob-iv-fixed',
        file: 'public/js/keys.js',
        suite: 'tests/frontend',
        desc: 'wrapped key blobs are sealed with an all-zero IV',
        find: '    const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));',
        replace: '    const iv = new Uint8Array(AES_IV_LENGTH);'
    },

    // ── what is allowed to persist ─────────────────────────────────
    {
        id: 'fe-persists-wrapped-private-key',
        file: 'public/js/state.js',
        suite: 'tests/frontend',
        desc: 'the sealed private key is written to localStorage again',
        // The regression CodeQL caught once already. Storage survives the tab;
        // the session key material must not.
        find: 'export function setWrappedPrivateKey(blob) { state.wrappedPrivateKey = blob; }',
        replace: "export function setWrappedPrivateKey(blob) { state.wrappedPrivateKey = blob; try { localStorage.setItem('privateKeyEnc', blob); } catch { /* non-DOM env */ } }"
    },

    // ── the KDF itself ─────────────────────────────────────────────
    //
    // The only mutant over public/vendor/. Everything else here breaks code
    // this project wrote; this one breaks the vendored Argon2id, because that
    // is where the corresponding real-world risk lives. Nobody edits
    // public/vendor/ by hand — `npm update` and scripts/vendor-noble.mjs do,
    // together, in a diff that reads as a lockfile bump.
    //
    // vendor-integrity.test.ts cannot see it: it proves the copy matches
    // node_modules, which stays true when node_modules is what changed. Nor can
    // any same-in-same-out test, since a swapped implementation is perfectly
    // self-consistent. Only a pinned vector notices, which is what
    // tests/frontend/argon2-known-answer.test.js is for.
    {
        id: 'fe-argon2id-is-argon2i',
        file: 'public/vendor/noble-hashes/argon2.js',
        suite: 'tests/frontend',
        desc: 'argon2id() silently computes Argon2i, changing every derived master key',
        find: 'const AT = { Argon2d: 0, Argon2i: 1, Argon2id: 2 };',
        replace: 'const AT = { Argon2d: 0, Argon2i: 1, Argon2id: 1 };'
    }
];
