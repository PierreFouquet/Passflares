import { sign } from 'jsonwebtoken';
import { VaultMetadata } from './types.js';
import { deriveScryptHash, verifyTurnstile } from './utils.js';
import { logAudit } from './auditLog.js';
import { CustomRequest, Env, User } from './types.js';
import { jsonResponse } from './utils.js';

const FAILED_ATTEMPTS_LIMIT = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes

export async function handleRegister(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { email, masterPassword, encryptionSalt, turnstileToken } = await request.json() as {
        email: string;
        masterPassword: string;
        encryptionSalt: string;
        turnstileToken?: string;
    };
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    // Rate limit by IP — same lockout policy as /login to prevent registration spam
    const ipKey = `rate_limit:register:${ipAddress}`;
    const failedAttempts = await env.RATE_LIMIT.get(ipKey);
    if (failedAttempts && parseInt(failedAttempts) >= FAILED_ATTEMPTS_LIMIT) {
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, reason: 'Rate limited' }, ipAddress, userAgent);
        return jsonResponse({ message: "Too many registration attempts. Try again later." }, 429);
    }

    if (!email || !masterPassword || !encryptionSalt) {
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Email, master password, and encryption salt are required." }, 400);
    }

    // Turnstile is required — fail closed so a missing or invalid token blocks registration.
    const turnstileOk = await verifyTurnstile(turnstileToken, env.TURNSTILE_KEY, ipAddress);
    if (!turnstileOk) {
        const newCount = failedAttempts ? parseInt(failedAttempts) + 1 : 1;
        await env.RATE_LIMIT.put(ipKey, newCount.toString(), { expirationTtl: LOCKOUT_DURATION / 1000 });
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

        // Derive hash for server-side storage
        const { hash: passwordHash, salt: storedSalt } = await deriveScryptHash(masterPassword);

        // Store user in D1 with separate salt and hash columns
        const { success } = await env.DB.prepare(
            "INSERT INTO users (email, password_hash, password_salt, encryption_salt) VALUES (?, ?, ?, ?)"
        ).bind(email, passwordHash, storedSalt, encryptionSalt).run();

        if (success) {
            await env.RATE_LIMIT.delete(ipKey);
            logAudit(env, ctx, null, 'REGISTER_SUCCESS', { email }, ipAddress, userAgent);
            return jsonResponse({ message: "User registered successfully." }, 201);
        } else {
            logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, reason: 'DB insert failed' }, ipAddress, userAgent);
            return jsonResponse({ message: "Failed to register user." }, 500);
        }
    } catch (error: any) {
        console.error("Registration error:", error);
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { email, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during registration." }, 500);
    }
}

export async function handleLogin(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { email, masterPassword, turnstileToken } = await request.json() as {
        email: string;
        masterPassword: string;
        turnstileToken?: string;
    };
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!email || !masterPassword) {
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Email and master password are required." }, 400);
    }

    // Rate limiting check
    const ipKey = `rate_limit:${ipAddress}`;
    const failedAttempts = await env.RATE_LIMIT.get(ipKey);
    if (failedAttempts && parseInt(failedAttempts) >= FAILED_ATTEMPTS_LIMIT) {
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, reason: 'Rate limited' }, ipAddress, userAgent);
        return jsonResponse({ message: "Too many failed attempts. Try again later." }, 429);
    }

    // Turnstile is required — fail closed so a missing or invalid token blocks login.
    const turnstileOk = await verifyTurnstile(turnstileToken, env.TURNSTILE_KEY, ipAddress);
    if (!turnstileOk) {
        const newCount = failedAttempts ? parseInt(failedAttempts) + 1 : 1;
        await env.RATE_LIMIT.put(ipKey, newCount.toString(), { expirationTtl: LOCKOUT_DURATION / 1000 });
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, reason: 'Turnstile failed' }, ipAddress, userAgent);
        return jsonResponse({ message: "CAPTCHA verification failed. Please try again." }, 403);
    }

    try {
        const user: User | null = await env.DB.prepare(
            "SELECT id, email, password_hash, password_salt, encryption_salt FROM users WHERE email = ?"
        ).bind(email).first();

        if (!user) {
            // Increment failed attempts
            const newCount = failedAttempts ? parseInt(failedAttempts) + 1 : 1;
            await env.RATE_LIMIT.put(ipKey, newCount.toString(), { expirationTtl: LOCKOUT_DURATION / 1000 });
            
            logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, reason: 'User not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Invalid credentials." }, 401);
        }

        // Verify master password hash
        const { hash: verifiedHash } = await deriveScryptHash(masterPassword, user.password_salt);
        if (verifiedHash !== user.password_hash) {
            // Increment failed attempts
            const newCount = failedAttempts ? parseInt(failedAttempts) + 1 : 1;
            await env.RATE_LIMIT.put(ipKey, newCount.toString(), { expirationTtl: LOCKOUT_DURATION / 1000 });
            
            logAudit(env, ctx, user.id, 'LOGIN_FAILURE', { email, reason: 'Password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Invalid credentials." }, 401);
        }

        // Reset failed attempts on successful login
        await env.RATE_LIMIT.delete(ipKey);

        // Generate JWT token
        const token = sign({ userId: user.id, email: user.email }, env.JWT_SECRET, { expiresIn: '1h' });

        logAudit(env, ctx, user.id, 'LOGIN_SUCCESS', { email }, ipAddress, userAgent);
        return jsonResponse({
            message: "Login successful.",
            userId: user.id,
            email: user.email,
            encryptionSalt: user.encryption_salt,
            token
        });

    } catch (error: any) {
        console.error("Login error:", error);
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during login." }, 500);
    }
}

export async function handleGetUserEncryptionSalt(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const userIdParam = request.params?.userId;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!request.user || request.user.userId !== parseInt(userIdParam || '0')) {
        logAudit(env, ctx, request.user?.userId || null, 'GET_SALT_FAILURE', { reason: 'Unauthorized user ID mismatch' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized: User ID mismatch." }, 403);
    }

    try {
        const user: User | null = await env.DB.prepare("SELECT encryption_salt FROM users WHERE id = ?").bind(request.user.userId).first();

        if (!user) {
            logAudit(env, ctx, request.user.userId, 'GET_SALT_FAILURE', { reason: 'User not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "User not found." }, 404);
        }

        logAudit(env, ctx, request.user.userId, 'GET_SALT_SUCCESS', {}, ipAddress, userAgent);
        return jsonResponse({ encryptionSalt: user.encryption_salt });
    } catch (error: any) {
        console.error("Get encryption salt error:", error);
        logAudit(env, ctx, request.user.userId, 'GET_SALT_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error." }, 500);
    }
}

export async function handleUpdateMasterPassword(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { oldMasterPassword, newMasterPassword, newEncryptionSalt } = await request.json() as { oldMasterPassword: string; newMasterPassword: string; newEncryptionSalt: string };
    const userIdParam = request.params?.userId;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!request.user || request.user.userId !== parseInt(userIdParam || '0')) {
        logAudit(env, ctx, request.user?.userId || null, 'UPDATE_PASSWORD_FAILURE', { reason: 'Unauthorized user ID mismatch' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized: User ID mismatch." }, 403);
    }

    if (!oldMasterPassword || !newMasterPassword || !newEncryptionSalt) {
        logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Old password, new password, and new encryption salt are required." }, 400);
    }

    try {
        const user: User | null = await env.DB.prepare("SELECT id, password_hash, password_salt FROM users WHERE id = ?").bind(request.user.userId).first();

        if (!user) {
            logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'User not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "User not found." }, 404);
        }

        // Verify old master password
        const { hash: verifiedOldHash } = await deriveScryptHash(oldMasterPassword, user.password_salt);
        if (verifiedOldHash !== user.password_hash) {
            logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'Old password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Old master password is incorrect." }, 401);
        }

        // Derive new hash for server-side storage
        const { hash: newPasswordHash, salt: newStoredSalt } = await deriveScryptHash(newMasterPassword);

        // Update user's password_hash and client-side encryption_salt
        const { success } = await env.DB.prepare(
            `UPDATE users SET password_hash = ?, password_salt = ?, encryption_salt = ? WHERE id = ?`
        ).bind(newPasswordHash, newStoredSalt, newEncryptionSalt, request.user.userId).run();

        if (success) {
            logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_SUCCESS', {}, ipAddress, userAgent);
            return jsonResponse({ message: "Master password updated successfully." });
        } else {
            logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'DB update failed' }, ipAddress, userAgent);
            return jsonResponse({ message: "Failed to update master password." }, 500);
        }
    } catch (error: any) {
        console.error("Update master password error:", error);
        logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during password update." }, 500);
    }
}

export async function handleDeleteAccount(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const userIdParam = request.params?.userId;
    const { masterPassword } = await request.json() as { masterPassword: string };
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!request.user || request.user.userId !== parseInt(userIdParam || '0')) {
        return jsonResponse({ message: "Unauthorized: User ID mismatch." }, 403);
    }

    if (!masterPassword) {
        return jsonResponse({ message: "Master password is required to confirm account deletion." }, 400);
    }

    const userId = request.user.userId;

    try {
        // Verify master password before deleting anything
        const user: User | null = await env.DB.prepare(
            "SELECT id, password_hash, password_salt FROM users WHERE id = ?"
        ).bind(userId).first();

        if (!user) {
            return jsonResponse({ message: "User not found." }, 404);
        }

        const { hash: verifiedHash } = await deriveScryptHash(masterPassword, user.password_salt);
        if (verifiedHash !== user.password_hash) {
            logAudit(env, ctx, userId, 'DELETE_ACCOUNT_FAILURE', { reason: 'Password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Master password is incorrect." }, 401);
        }

        // 1. Find all personal vaults owned by this user
        const ownedVaults = await env.DB.prepare(
            "SELECT id, r2_object_key FROM vaults WHERE owner_id = ? AND owner_type = 'user'"
        ).bind(`user_${userId}`).all().then(r => r.results as unknown as Pick<VaultMetadata, 'id' | 'r2_object_key'>[]);

        // 2. Delete R2 objects for each vault
        for (const vault of ownedVaults) {
            await env.VAULTS.delete(vault.r2_object_key);
        }

        // 3. Delete owned vault records (FK cascade removes vault_access_controls)
        if (ownedVaults.length > 0) {
            const deleteVault = env.DB.prepare('DELETE FROM vaults WHERE id = ?');
            await env.DB.batch(ownedVaults.map(v => deleteVault.bind(v.id)));
        }

        // 4. Remove user from shared vault access controls
        await env.DB.prepare(
            "DELETE FROM vault_access_controls WHERE entity_id = ? AND entity_type = 'user'"
        ).bind(`user_${userId}`).run();

        // 5. Delete user record (FK cascade removes user_organizations; audit_logs.user_id set to NULL)
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