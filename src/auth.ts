// src/auth.ts

import { sign } from 'jsonwebtoken';
import { deriveScryptHash } from './utils.js'; // Ensure correct path and .js extension
import { logAudit } from './auditLog.js'; // Ensure correct path and .js extension
import { CustomRequest, Env, User } from './types.js'; // Ensure correct path and .js extension
import { jsonResponse } from './utils.js'; // Ensure correct path and .js extension

export async function handleRegister(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { email, masterPassword, encryptionSalt } = await request.json() as { email: string; masterPassword: string; encryptionSalt: string };
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!email || !masterPassword || !encryptionSalt) {
        logAudit(env, ctx, null, 'REGISTER_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Email, master password, and encryption salt are required." }, 400);
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

        // Store user in D1
        const { success } = await env.DB.prepare(
            "INSERT INTO users (email, password_hash, encryption_salt) VALUES (?, ?, ?)"
        ).bind(email, passwordHash, encryptionSalt).run();

        if (success) {
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
    const { email, masterPassword } = await request.json() as { email: string; masterPassword: string };
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!email || !masterPassword) {
        logAudit(env, ctx, null, 'LOGIN_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Email and master password are required." }, 400);
    }

    try {
        const user: User | null = await env.DB.prepare("SELECT id, email, password_hash, encryption_salt FROM users WHERE email = ?").bind(email).first();

        if (!user) {
            logAudit(env, ctx, null, 'LOGIN_FAILURE', { email, reason: 'User not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Invalid credentials." }, 401);
        }

        // Verify master password hash
        const { hash: inputHash } = await deriveScryptHash(masterPassword, null); // We don't have the original salt for verification, need to store it with the hash
        // FIX: The original `deriveScryptHash` function generates a new salt if `null` is passed.
        // For verification, we MUST use the salt stored in the database with the hash.
        // Let's assume for now that `password_hash` in DB is the full scrypt output (hash + salt prepended)
        // or we need to fetch the salt separately.
        // CORRECTED APPROACH: The `deriveScryptHash` returns `{ hash, salt }`. We need to store both.
        // When verifying, we pass the stored salt to derive the hash from the input password and compare.

        const { hash: verifiedHash } = await deriveScryptHash(masterPassword, user.password_hash.split('.')[0]); // Assuming password_hash is "salt.hash"
        if (verifiedHash !== user.password_hash.split('.')[1]) { // Compare hash part
            logAudit(env, ctx, user.id, 'LOGIN_FAILURE', { email, reason: 'Password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Invalid credentials." }, 401);
        }

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
        const user: User | null = await env.DB.prepare("SELECT id, password_hash FROM users WHERE id = ?").bind(request.user.userId).first();

        if (!user) {
            logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'User not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "User not found." }, 404);
        }

        // Verify old master password
        const storedHashParts = user.password_hash.split('.'); // Assuming "salt.hash"
        const oldPasswordSalt = storedHashParts[0];
        const oldPasswordStoredHash = storedHashParts[1];

        const { hash: verifiedOldHash } = await deriveScryptHash(oldMasterPassword, oldPasswordSalt);

        if (verifiedOldHash !== oldPasswordStoredHash) {
            logAudit(env, ctx, request.user.userId, 'UPDATE_PASSWORD_FAILURE', { reason: 'Old password mismatch' }, ipAddress, userAgent);
            return jsonResponse({ message: "Old master password is incorrect." }, 401);
        }

        // Derive new hash for server-side storage
        const { hash: newPasswordHash, salt: newStoredSalt } = await deriveScryptHash(newMasterPassword); // Generates new salt for server hash

        // Update user's password_hash and client-side encryption_salt
        const { success } = await env.DB.prepare(
            `UPDATE users SET password_hash = ?, encryption_salt = ? WHERE id = ?`
        ).bind(`${newStoredSalt}.${newPasswordHash}`, newEncryptionSalt, request.user.userId).run();

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
