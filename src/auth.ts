import { sign } from 'jsonwebtoken';
import { VaultMetadata } from './types.js';
import {
    deriveScryptHash,
    verifyTurnstile,
    timingSafeEqualHex,
    normalizeEmail,
    isValidEmail,
    parseId,
    parseCounter,
    decoyKdfSalt
} from './utils.js';
import { logAudit } from './auditLog.js';
import {
    CustomRequest,
    Env,
    User,
    KdfParams,
    AUTH_VERSION_LEGACY,
    AUTH_VERSION_KEY_HIERARCHY,
    versionedObjectKey
} from './types.js';
import { jsonResponse } from './utils.js';

const FAILED_ATTEMPTS_LIMIT = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

// Argon2id profile handed to new clients. Mirrors ARGON2_PARAMS in
// public/js/constants.js; stored per-user at registration so raising these later
// never locks out an account enrolled under the old numbers.
const DEFAULT_KDF_PARAMS: KdfParams = { m: 47104, t: 1, p: 1, len: 32 };

// v2 accounts have no legacy PBKDF2 salt. The column is NOT NULL from 0001 and
// SQLite can't relax that without a table rebuild, so they store the empty
// string — which every read path treats as "no legacy key material".
const NO_LEGACY_SALT = '';

/** Rejects oversized field values before they reach scrypt or D1. */
function isSaneSecret(value: unknown, max = 512): value is string {
    return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function parseKdfParams(raw: unknown): KdfParams | null {
    if (typeof raw !== 'object' || raw === null) return null;
    const { m, t, p, len } = raw as Record<string, unknown>;
    const ok = (v: unknown, lo: number, hi: number) =>
        typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi;
    // Floors matter: a client that talked the server into m=8,t=1 would be
    // storing a verifier derived from an effectively unstretched password.
    if (!ok(m, 8192, 1048576) || !ok(t, 1, 10) || !ok(p, 1, 4) || !ok(len, 32, 64)) return null;
    return { m: m as number, t: t as number, p: p as number, len: len as number };
}

/**
 * GET /api/auth/params?email=
 *
 * Tells the client which authentication flow to run and, for v2, the Argon2id
 * inputs needed to derive the master key. Unauthenticated by necessity — the
 * client needs this *before* it can produce an authSecret.
 *
 * Unknown emails get deterministic decoy parameters rather than a 404, so this
 * is not an account-existence oracle. Rate-limited per IP because it is the one
 * pre-auth endpoint that touches the users table.
 */
export async function handleAuthParams(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const url = new URL(request.url);
    const email = normalizeEmail(url.searchParams.get('email'));

    const ipKey = `rate_limit:authparams:${ipAddress}`;
    const attempts = parseCounter(await env.RATE_LIMIT.get(ipKey));
    if (attempts >= FAILED_ATTEMPTS_LIMIT * 6) {
        return jsonResponse({ message: "Too many requests. Try again later." }, 429);
    }
    await env.RATE_LIMIT.put(ipKey, String(attempts + 1), { expirationTtl: LOCKOUT_DURATION / 1000 });

    // A malformed email can't belong to an account, but answering differently
    // would still distinguish it. Fall through to the decoy.
    const decoy = {
        authVersion: AUTH_VERSION_KEY_HIERARCHY,
        kdfSalt: decoyKdfSalt(email, env.JWT_SECRET),
        kdfParams: DEFAULT_KDF_PARAMS
    };

    if (!email || !isValidEmail(email)) return jsonResponse(decoy);

    try {
        const user = await env.DB.prepare(
            "SELECT auth_version, kdf_salt, kdf_params FROM users WHERE email = ?"
        ).bind(email).first<Pick<User, 'auth_version' | 'kdf_salt' | 'kdf_params'>>();

        if (!user) return jsonResponse(decoy);

        if (user.auth_version === AUTH_VERSION_LEGACY) {
            // The legacy client flow needs no KDF parameters — it sends the
            // password. Saying so is not a leak: it only distinguishes old
            // accounts from new ones, and the upgrade removes the distinction.
            return jsonResponse({ authVersion: AUTH_VERSION_LEGACY });
        }

        return jsonResponse({
            authVersion: AUTH_VERSION_KEY_HIERARCHY,
            kdfSalt: user.kdf_salt,
            kdfParams: user.kdf_params ? JSON.parse(user.kdf_params) : DEFAULT_KDF_PARAMS
        });
    } catch (error: any) {
        console.error("Auth params error:", error);
        return jsonResponse(decoy);
    }
}

/**
 * POST /api/register
 *
 * Only ever creates auth_version 2 accounts. The client has already run
 * Argon2id + HKDF and generated its keypair, so the master password itself
 * never appears in this request.
 */
export async function handleRegister(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const body = await request.json() as {
        email?: string;
        authSecret?: string;
        kdfSalt?: string;
        kdfParams?: unknown;
        publicKey?: string;
        privateKeyEnc?: string;
        turnstileToken?: string;
    };
    const email = normalizeEmail(body.email);
    const { authSecret, kdfSalt, publicKey, privateKeyEnc, turnstileToken } = body;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    // Rate limit by IP — same lockout policy as /login to prevent registration spam
    const ipKey = `rate_limit:register:${ipAddress}`;
    const failedAttempts = parseCounter(await env.RATE_LIMIT.get(ipKey));
    if (failedAttempts >= FAILED_ATTEMPTS_LIMIT) {
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, reason: 'Rate limited' }, ipAddress, userAgent);
        return jsonResponse({ message: "Too many registration attempts. Try again later." }, 429);
    }

    const kdfParams = parseKdfParams(body.kdfParams);
    if (!email || !isSaneSecret(authSecret) || !isSaneSecret(kdfSalt, 128) || !kdfParams ||
        !isSaneSecret(publicKey, 1024) || !isSaneSecret(privateKeyEnc, 4096)) {
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { reason: 'Missing or invalid fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Registration payload is incomplete or invalid." }, 400);
    }
    if (!isValidEmail(email)) {
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { reason: 'Invalid email' }, ipAddress, userAgent);
        return jsonResponse({ message: "Please provide a valid email address." }, 400);
    }

    // Turnstile is required — fail closed so a missing or invalid token blocks registration.
    const turnstileOk = await verifyTurnstile(turnstileToken, env.TURNSTILE_KEY, ipAddress);
    if (!turnstileOk) {
        await env.RATE_LIMIT.put(ipKey, String(failedAttempts + 1), { expirationTtl: LOCKOUT_DURATION / 1000 });
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, reason: 'Turnstile failed' }, ipAddress, userAgent);
        return jsonResponse({ message: "CAPTCHA verification failed. Please try again." }, 403);
    }

    try {
        // Check if user already exists
        const existingUser: User | null = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
        if (existingUser) {
            logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, reason: 'User already exists' }, ipAddress, userAgent);
            return jsonResponse({ message: "User with this email already exists." }, 409);
        }

        // scrypt over the *auth secret*, not the password. The password is not in
        // this request and never has been.
        const { hash: passwordHash, salt: storedSalt } = await deriveScryptHash(authSecret);

        const insertUser = await env.DB.prepare(
            `INSERT INTO users (email, password_hash, password_salt, encryption_salt, auth_version, kdf_salt, kdf_params, legacy_vaults_pending)
             VALUES (?, ?, ?, ?, ?, ?, ?, 0)`
        ).bind(
            email, passwordHash, storedSalt, NO_LEGACY_SALT,
            AUTH_VERSION_KEY_HIERARCHY, kdfSalt, JSON.stringify(kdfParams)
        ).run();

        if (!insertUser.success || !insertUser.meta?.last_row_id) {
            logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, reason: 'DB insert failed' }, ipAddress, userAgent);
            return jsonResponse({ message: "Failed to register user." }, 500);
        }

        const userId = insertUser.meta.last_row_id;

        // The keypair is useless without the account, so a failure here must not
        // leave a keyless user behind — compensate by removing the row.
        const insertKeys = await env.DB.prepare(
            `INSERT INTO user_keys (user_id, public_key, private_key_enc) VALUES (?, ?, ?)`
        ).bind(userId, publicKey, privateKeyEnc).run();

        if (!insertKeys.success) {
            await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
            logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, reason: 'Key insert failed' }, ipAddress, userAgent);
            return jsonResponse({ message: "Failed to register user." }, 500);
        }

        await env.RATE_LIMIT.delete(ipKey);
        logAudit(env, ctx, null, 'REGISTER_SUCCESS', { email }, ipAddress, userAgent);
        return jsonResponse({ message: "User registered successfully." }, 201);
    } catch (error: any) {
        console.error("Registration error:", error);
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during registration." }, 500);
    }
}

/**
 * POST /api/login
 *
 * Dual-stack for the duration of the migration:
 *   auth_version 2 -> { email, authSecret }     the password never leaves the browser
 *   auth_version 1 -> { email, masterPassword } legacy, accepted one last time so the
 *                                               client can perform the in-place upgrade
 *
 * A v1 account is the only case where a password still reaches this worker, and
 * only until its owner next signs in.
 */
export async function handleLogin(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const body = await request.json() as {
        email?: string;
        authSecret?: string;
        masterPassword?: string;
        turnstileToken?: string;
    };
    const email = normalizeEmail(body.email);
    const { authSecret, masterPassword, turnstileToken } = body;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    const presentedSecret = authSecret ?? masterPassword;
    if (!email || !isSaneSecret(presentedSecret, 4096)) {
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Email and credentials are required." }, 400);
    }

    // Rate limiting check
    const ipKey = `rate_limit:${ipAddress}`;
    const failedAttempts = parseCounter(await env.RATE_LIMIT.get(ipKey));
    if (failedAttempts >= FAILED_ATTEMPTS_LIMIT) {
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, reason: 'Rate limited' }, ipAddress, userAgent);
        return jsonResponse({ message: "Too many failed attempts. Try again later." }, 429);
    }
    const bumpFailures = () =>
        env.RATE_LIMIT.put(ipKey, String(failedAttempts + 1), { expirationTtl: LOCKOUT_DURATION / 1000 });

    // Turnstile is required — fail closed so a missing or invalid token blocks login.
    const turnstileOk = await verifyTurnstile(turnstileToken, env.TURNSTILE_KEY, ipAddress);
    if (!turnstileOk) {
        await bumpFailures();
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, reason: 'Turnstile failed' }, ipAddress, userAgent);
        return jsonResponse({ message: "CAPTCHA verification failed. Please try again." }, 403);
    }

    try {
        const user = await env.DB.prepare(
            "SELECT users.id, users.email, users.password_hash, users.password_salt, users.encryption_salt, users.auth_version, users.legacy_vaults_pending, user_totp.enabled AS totp_enabled FROM users LEFT JOIN user_totp ON user_totp.user_id = users.id WHERE users.email = ?"
        ).bind(email).first() as (User & { totp_enabled: number | null }) | null;

        if (!user) {
            await bumpFailures();
            logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, reason: 'User not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Invalid credentials." }, 401);
        }

        // Refuse to accept a plaintext password for an already-upgraded account,
        // and refuse an authSecret for one that hasn't upgraded — otherwise a
        // downgrade attack could push a v2 user back onto the legacy path.
        const usingLegacyFlow = authSecret === undefined;
        if (usingLegacyFlow !== (user.auth_version === AUTH_VERSION_LEGACY)) {
            await bumpFailures();
            logAudit(env, ctx, user.id, 'LOGIN_FAILURE', { email, reason: 'Auth version mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Invalid credentials." }, 401);
        }

        const { hash: verifiedHash } = await deriveScryptHash(presentedSecret, user.password_salt);
        if (!timingSafeEqualHex(verifiedHash, user.password_hash)) {
            await bumpFailures();
            logAudit(env, ctx, user.id, 'LOGIN_FAILURE', { email, reason: 'Credential mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Invalid credentials." }, 401);
        }

        // Reset failed attempts on successful login
        await env.RATE_LIMIT.delete(ipKey);

        // If the user has 2FA enabled, don't issue a session yet. Return a
        // short-lived token scoped to the 2FA step only — handleLoginVerify2fa
        // exchanges it (plus a TOTP/recovery code) for the real session token,
        // and the auth middleware rejects scope:'2fa' on protected routes.
        if (user.totp_enabled === 1) {
            const tempToken = sign({ sub: user.id, email: user.email, scope: '2fa' }, env.JWT_SECRET, { expiresIn: '5m' });
            logAudit(env, ctx, user.id, 'LOGIN_2FA_REQUIRED', { email }, ipAddress, userAgent);
            return jsonResponse({ message: "Two-factor authentication required.", requires2FA: true, tempToken });
        }

        const token = sign({ userId: user.id, email: user.email }, env.JWT_SECRET, { expiresIn: '1h' });
        logAudit(env, ctx, user.id, 'LOGIN_SUCCESS', { email, authVersion: user.auth_version }, ipAddress, userAgent);
        return jsonResponse(await buildLoginResponse(env, user, token));
    } catch (error: any) {
        console.error("Login error:", error);
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during login." }, 500);
    }
}

/**
 * The post-authentication payload, shared by the single-step and post-2FA paths.
 *
 * v2 clients get their wrapped keypair (useless without the KEK, which only the
 * browser can derive). v1 clients still get encryption_salt, because they are
 * about to use it to decrypt their vaults one last time and upgrade.
 */
export async function buildLoginResponse(
    env: Env,
    user: Pick<User, 'id' | 'email' | 'encryption_salt' | 'auth_version' | 'legacy_vaults_pending'>,
    token: string
): Promise<Record<string, any>> {
    const base: Record<string, any> = {
        message: "Login successful.",
        userId: user.id,
        email: user.email,
        authVersion: user.auth_version,
        token
    };

    if (user.auth_version === AUTH_VERSION_LEGACY) {
        base.encryptionSalt = user.encryption_salt;
        return base;
    }

    const keys = await env.DB.prepare(
        "SELECT public_key, private_key_enc FROM user_keys WHERE user_id = ?"
    ).bind(user.id).first<{ public_key: string; private_key_enc: string }>();

    base.publicKey = keys?.public_key ?? null;
    base.privateKeyEnc = keys?.private_key_enc ?? null;
    base.legacyVaultsPending = user.legacy_vaults_pending;
    // Still needed to rescue organisation vaults that predate the upgrade (#69).
    if (user.legacy_vaults_pending > 0) base.encryptionSalt = user.encryption_salt;
    return base;
}

/**
 * POST /api/auth/upgrade
 *
 * The one-shot, in-place migration from auth_version 1 to 2. Called by the client
 * immediately after a successful legacy login, while it still holds the password
 * in memory and can therefore derive both the old PBKDF2 key and the new hierarchy.
 *
 * Everything lands in a single D1.batch(): either the account is fully on v2 with
 * every re-encrypted vault pointing at its new blob, or it is untouched on v1 with
 * the original blobs still live. There is no interior state where the stored
 * credentials and the reachable ciphertext disagree — which is the failure mode
 * that makes #70 a data-loss bug.
 */
export async function handleAuthUpgrade(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const userId = request.user!.userId;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    const body = await request.json() as {
        authSecret?: string;
        kdfSalt?: string;
        kdfParams?: unknown;
        publicKey?: string;
        privateKeyEnc?: string;
        vaults?: Array<{ vaultId: number; wrappedKey: string; ephemeralPubkey: string }>;
        legacyVaultsPending?: number;
    };

    const kdfParams = parseKdfParams(body.kdfParams);
    const { authSecret, kdfSalt, publicKey, privateKeyEnc } = body;
    if (!isSaneSecret(authSecret) || !isSaneSecret(kdfSalt, 128) || !kdfParams ||
        !isSaneSecret(publicKey, 1024) || !isSaneSecret(privateKeyEnc, 4096)) {
        return jsonResponse({ message: "Upgrade payload is incomplete or invalid." }, 400);
    }

    const shares = Array.isArray(body.vaults) ? body.vaults : [];
    for (const share of shares) {
        if (!Number.isInteger(share?.vaultId) ||
            !isSaneSecret(share?.wrappedKey, 4096) ||
            !isSaneSecret(share?.ephemeralPubkey, 1024)) {
            return jsonResponse({ message: "Upgrade payload contains an invalid vault key share." }, 400);
        }
    }

    try {
        const user = await env.DB.prepare(
            "SELECT id, auth_version FROM users WHERE id = ?"
        ).bind(userId).first<Pick<User, 'id' | 'auth_version'>>();

        if (!user) return jsonResponse({ message: "User not found." }, 404);
        if (user.auth_version !== AUTH_VERSION_LEGACY) {
            // Idempotent: a retry after a partial client-side failure, or two
            // tabs racing, must not clobber the keypair already in place.
            return jsonResponse({ message: "Account is already upgraded.", alreadyUpgraded: true });
        }

        // Only vaults this user personally owns may be re-keyed here. An org
        // vault re-keyed by one member would become unreadable to the rest.
        const ownedVaultRows = await env.DB.prepare(
            "SELECT id FROM vaults WHERE owner_id = ? AND owner_type = 'user'"
        ).bind(`user_${userId}`).all().then(r => r.results as unknown as { id: number }[]);
        const ownedVaultIds = new Set(ownedVaultRows.map(v => v.id));

        const rejected = shares.filter(s => !ownedVaultIds.has(s.vaultId));
        if (rejected.length > 0) {
            logAudit(env, ctx, userId, 'AUTH_UPGRADE_FAILURE',
                { reason: 'Share for non-owned vault', vaultIds: rejected.map(r => r.vaultId) }, ipAddress, userAgent);
            return jsonResponse({ message: "Cannot re-key a vault you do not own." }, 403);
        }

        const { hash: passwordHash, salt: passwordSalt } = await deriveScryptHash(authSecret);

        const statements = [
            env.DB.prepare(
                `INSERT INTO user_keys (user_id, public_key, private_key_enc) VALUES (?, ?, ?)
                 ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key,
                     private_key_enc = excluded.private_key_enc, updated_at = CURRENT_TIMESTAMP`
            ).bind(userId, publicKey, privateKeyEnc)
        ];

        const shareInsert = env.DB.prepare(
            `INSERT INTO vault_key_shares (vault_id, user_id, wrapped_key, ephemeral_pubkey, key_version, created_by)
             VALUES (?, ?, ?, ?, 'v2', ?)
             ON CONFLICT(vault_id, user_id) DO UPDATE SET wrapped_key = excluded.wrapped_key,
                 ephemeral_pubkey = excluded.ephemeral_pubkey, key_version = excluded.key_version`
        );
        const versionFlip = env.DB.prepare("UPDATE vaults SET current_key_version = 'v2' WHERE id = ?");
        for (const share of shares) {
            statements.push(shareInsert.bind(share.vaultId, userId, share.wrappedKey, share.ephemeralPubkey, userId));
            // The client has already written <r2_object_key>.v2; this flip is what
            // makes it live. Until it commits, reads keep serving the v1 blob.
            statements.push(versionFlip.bind(share.vaultId));
        }

        // Organisation vaults are not re-keyed here — only their creator can
        // decrypt them (#69), and that has to happen when they next open one.
        // encryption_salt is retained until that count reaches zero.
        const pending = await env.DB.prepare(
            `SELECT COUNT(*) AS cnt FROM vaults v
             JOIN vault_access_controls vac ON v.id = vac.vault_id
             JOIN user_organizations uo ON vac.entity_id = 'org_' || uo.organization_id AND vac.entity_type = 'organization'
             WHERE uo.user_id = ? AND v.owner_type = 'organization' AND v.current_key_version = 'v1'`
        ).bind(userId).first<{ cnt: number }>();
        const legacyVaultsPending = pending?.cnt ?? 0;

        statements.push(
            env.DB.prepare(
                `UPDATE users SET auth_version = ?, password_hash = ?, password_salt = ?,
                     kdf_salt = ?, kdf_params = ?, legacy_vaults_pending = ?,
                     encryption_salt = CASE WHEN ? > 0 THEN encryption_salt ELSE '' END
                 WHERE id = ? AND auth_version = ?`
            ).bind(
                AUTH_VERSION_KEY_HIERARCHY, passwordHash, passwordSalt,
                kdfSalt, JSON.stringify(kdfParams), legacyVaultsPending,
                legacyVaultsPending, userId, AUTH_VERSION_LEGACY
            )
        );

        await env.DB.batch(statements);

        logAudit(env, ctx, userId, 'AUTH_UPGRADE_SUCCESS',
            { vaultsRekeyed: shares.length, legacyVaultsPending }, ipAddress, userAgent);
        return jsonResponse({
            message: "Account upgraded.",
            authVersion: AUTH_VERSION_KEY_HIERARCHY,
            legacyVaultsPending
        });
    } catch (error: any) {
        console.error("Auth upgrade error:", error);
        logAudit(env, ctx, userId, 'AUTH_UPGRADE_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during account upgrade." }, 500);
    }
}

/**
 * GET /api/users/:userId/encryption-salt
 *
 * Legacy PBKDF2 salt. Only meaningful for accounts that still hold v1 ciphertext;
 * returns null once the last one has been re-keyed.
 */
export async function handleGetUserEncryptionSalt(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestedId = parseId(request.params?.userId);
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!request.user || requestedId === null || request.user.userId !== requestedId) {
        logAudit(env, ctx, request.user?.userId || null, 'GET_SALT_FAILURE', { reason: 'Unauthorized user ID mismatch' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized: User ID mismatch." }, 403);
    }

    try {
        const user = await env.DB.prepare(
            "SELECT encryption_salt, legacy_vaults_pending FROM users WHERE id = ?"
        ).bind(request.user.userId).first<Pick<User, 'encryption_salt' | 'legacy_vaults_pending'>>();

        if (!user) {
            logAudit(env, ctx, request.user.userId, 'GET_SALT_FAILURE', { reason: 'User not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "User not found." }, 404);
        }

        logAudit(env, ctx, request.user.userId, 'GET_SALT_SUCCESS', {}, ipAddress, userAgent);
        return jsonResponse({
            encryptionSalt: user.encryption_salt || null,
            legacyVaultsPending: user.legacy_vaults_pending
        });
    } catch (error: any) {
        console.error("Get encryption salt error:", error);
        logAudit(env, ctx, request.user.userId, 'GET_SALT_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error." }, 500);
    }
}

/**
 * GET /api/users/:userId/public-key
 *
 * A member's public key, so an admin can wrap a vault key for them. Only
 * disclosed to someone who shares an organisation with the target — public keys
 * are not secret, but this shouldn't double as an account enumeration endpoint.
 */
export async function handleGetUserPublicKey(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const targetId = parseId(request.params?.userId);
    if (targetId === null) return jsonResponse({ message: "Invalid user ID." }, 400);

    const requesterId = request.user!.userId;

    try {
        if (targetId !== requesterId) {
            const shared = await env.DB.prepare(
                `SELECT 1 AS ok FROM user_organizations a
                 JOIN user_organizations b ON a.organization_id = b.organization_id
                 WHERE a.user_id = ? AND b.user_id = ? LIMIT 1`
            ).bind(requesterId, targetId).first<{ ok: number }>();
            if (!shared) return jsonResponse({ message: "Not found." }, 404);
        }

        const keys = await env.DB.prepare(
            "SELECT public_key FROM user_keys WHERE user_id = ?"
        ).bind(targetId).first<{ public_key: string }>();

        if (!keys) {
            // A member who hasn't upgraded yet has no public key, so nothing can
            // be wrapped for them. The client needs to distinguish this from
            // "no such user" to explain the pending state honestly.
            return jsonResponse({ userId: targetId, publicKey: null, reason: 'not_upgraded' }, 200);
        }
        return jsonResponse({ userId: targetId, publicKey: keys.public_key });
    } catch (error: any) {
        console.error("Get public key error:", error);
        return jsonResponse({ message: "Internal Server Error." }, 500);
    }
}

/**
 * PUT /api/users/:userId/update-password
 *
 * For v2 accounts this is now cheap and safe: rotating the master password
 * changes the Argon2id salt, the auth verifier and the wrapped private key —
 * three columns. Vault ciphertext is never touched, which is what removes the
 * data-loss window described in #70.
 */
export async function handleUpdateMasterPassword(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const body = await request.json() as {
        oldAuthSecret?: string;
        newAuthSecret?: string;
        newKdfSalt?: string;
        newKdfParams?: unknown;
        newPrivateKeyEnc?: string;
    };
    const requestedId = parseId(request.params?.userId);
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!request.user || requestedId === null || request.user.userId !== requestedId) {
        logAudit(env, ctx, request.user?.userId || null, 'UPDATE_PASSWORD_FAILURE', { reason: 'Unauthorized user ID mismatch' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized: User ID mismatch." }, 403);
    }

    const newKdfParams = parseKdfParams(body.newKdfParams);
    const { oldAuthSecret, newAuthSecret, newKdfSalt, newPrivateKeyEnc } = body;
    if (!isSaneSecret(oldAuthSecret) || !isSaneSecret(newAuthSecret) ||
        !isSaneSecret(newKdfSalt, 128) || !newKdfParams || !isSaneSecret(newPrivateKeyEnc, 4096)) {
        logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Password change payload is incomplete or invalid." }, 400);
    }

    try {
        const user = await env.DB.prepare(
            "SELECT id, password_hash, password_salt, auth_version FROM users WHERE id = ?"
        ).bind(request.user.userId).first<Pick<User, 'id' | 'password_hash' | 'password_salt' | 'auth_version'>>();

        if (!user) {
            logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'User not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "User not found." }, 404);
        }
        if (user.auth_version !== AUTH_VERSION_KEY_HIERARCHY) {
            // A v1 account must complete its upgrade first; there is no sane way
            // to rotate a password that is still doubling as the vault key.
            return jsonResponse({ message: "Please sign out and sign back in before changing your password." }, 409);
        }

        const { hash: verifiedOldHash } = await deriveScryptHash(oldAuthSecret, user.password_salt);
        if (!timingSafeEqualHex(verifiedOldHash, user.password_hash)) {
            logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'Old password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Old master password is incorrect." }, 401);
        }

        const { hash: newPasswordHash, salt: newStoredSalt } = await deriveScryptHash(newAuthSecret);

        // One batch: the verifier and the re-wrapped private key must move
        // together, or the account is locked out of its own vault keys.
        await env.DB.batch([
            env.DB.prepare(
                `UPDATE users SET password_hash = ?, password_salt = ?, kdf_salt = ?, kdf_params = ? WHERE id = ?`
            ).bind(newPasswordHash, newStoredSalt, newKdfSalt, JSON.stringify(newKdfParams), request.user.userId),
            env.DB.prepare(
                `UPDATE user_keys SET private_key_enc = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?`
            ).bind(newPrivateKeyEnc, request.user.userId)
        ]);

        logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_SUCCESS', {}, ipAddress, userAgent);
        return jsonResponse({ message: "Master password updated successfully." });
    } catch (error: any) {
        console.error("Update master password error:", error);
        logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during password update." }, 500);
    }
}

export async function handleDeleteAccount(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestedId = parseId(request.params?.userId);
    const body = await request.json() as { authSecret?: string; masterPassword?: string };
    const presentedSecret = body.authSecret ?? body.masterPassword;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!request.user || requestedId === null || request.user.userId !== requestedId) {
        return jsonResponse({ message: "Unauthorized: User ID mismatch." }, 403);
    }

    if (!isSaneSecret(presentedSecret, 4096)) {
        return jsonResponse({ message: "Master password is required to confirm account deletion." }, 400);
    }

    const userId = request.user.userId;

    try {
        // Verify credentials before deleting anything
        const user = await env.DB.prepare(
            "SELECT id, password_hash, password_salt, auth_version FROM users WHERE id = ?"
        ).bind(userId).first<Pick<User, 'id' | 'password_hash' | 'password_salt' | 'auth_version'>>();

        if (!user) {
            return jsonResponse({ message: "User not found." }, 404);
        }

        const usingLegacyFlow = body.authSecret === undefined;
        if (usingLegacyFlow !== (user.auth_version === AUTH_VERSION_LEGACY)) {
            logAudit(env, ctx, userId, 'DELETE_ACCOUNT_FAILURE', { reason: 'Auth version mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Master password is incorrect." }, 401);
        }

        const { hash: verifiedHash } = await deriveScryptHash(presentedSecret, user.password_salt);
        if (!timingSafeEqualHex(verifiedHash, user.password_hash)) {
            logAudit(env, ctx, userId, 'DELETE_ACCOUNT_FAILURE', { reason: 'Password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Master password is incorrect." }, 401);
        }

        // 1. Find all personal vaults owned by this user
        const ownedVaults = await env.DB.prepare(
            "SELECT id, r2_object_key, current_key_version FROM vaults WHERE owner_id = ? AND owner_type = 'user'"
        ).bind(`user_${userId}`).all().then(r => r.results as unknown as Pick<VaultMetadata, 'id' | 'r2_object_key' | 'current_key_version'>[]);

        // 2. Delete R2 objects for each vault. Both key versions may exist if the
        //    account upgraded — the pre-upgrade blob is only swept lazily.
        for (const vault of ownedVaults) {
            await env.VAULTS.delete(vault.r2_object_key);
            if (vault.current_key_version && vault.current_key_version !== 'v1') {
                await env.VAULTS.delete(versionedObjectKey(vault.r2_object_key, vault.current_key_version));
            }
        }

        // 3. Delete owned vault records (FK cascade removes vault_access_controls
        //    and vault_key_shares)
        if (ownedVaults.length > 0) {
            const deleteVault = env.DB.prepare('DELETE FROM vaults WHERE id = ?');
            await env.DB.batch(ownedVaults.map(v => deleteVault.bind(v.id)));
        }

        // 4. Remove user from shared vault access controls
        await env.DB.prepare(
            "DELETE FROM vault_access_controls WHERE entity_id = ? AND entity_type = 'user'"
        ).bind(`user_${userId}`).run();

        // 4b. Remove 2FA secret + recovery codes (also covered by FK cascade)
        await env.DB.prepare("DELETE FROM user_recovery_codes WHERE user_id = ?").bind(userId).run();
        await env.DB.prepare("DELETE FROM user_totp WHERE user_id = ?").bind(userId).run();

        // 5. Delete user record (FK cascade removes user_organizations, user_keys,
        //    vault_key_shares; audit_logs.user_id set to NULL)
        await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();

        // 6. Clear any rate limit entries for this user's recent IPs (best-effort)
        if (ipAddress) {
            await env.RATE_LIMIT.delete(`rate_limit:${ipAddress}`);
        }

        logAudit(env, ctx, null, 'DELETE_ACCOUNT_SUCCESS', { userId }, ipAddress, userAgent);
        return new Response(null, { status: 204 });
    } catch (error: any) {
        console.error("Delete account error:", error);
        logAudit(env, ctx, userId, 'DELETE_ACCOUNT_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during account deletion." }, 500);
    }
}
