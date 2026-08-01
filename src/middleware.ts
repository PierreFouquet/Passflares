// src/middleware.ts

import { verify } from 'jsonwebtoken';
import { logAudit } from './auditLog.js';
import { CustomRequest, Env, VaultAccessControl } from './types.js';
import { jsonResponse, parseId } from './utils.js';

export type AccessLevel = 'read' | 'write' | 'manage';

const PERMISSION_RANK: Record<AccessLevel, number> = { read: 1, write: 2, manage: 3 };

export function permissionSatisfies(has: AccessLevel, required: AccessLevel): boolean {
    return PERMISSION_RANK[has] >= PERMISSION_RANK[required];
}

/**
 * Resolves a user's effective permission on a vault: direct ownership, then an
 * explicit user grant, then an organisation grant.
 *
 * Extracted from checkVaultPermission so endpoints that act on several vaults in
 * one request (the key-version commit, bulk share writes) can enforce the same
 * rules per vault instead of re-deriving them.
 *
 * @returns the level, or null if the user has no access at all
 */
export async function resolveVaultAccess(
    env: Env,
    userId: number,
    vaultId: number
): Promise<AccessLevel | null> {
    const directOwner = await env.DB.prepare(
        "SELECT id FROM vaults WHERE id = ? AND owner_id = ? AND owner_type = 'user'"
    ).bind(vaultId, `user_${userId}`).first<{ id: number }>();
    if (directOwner) return 'manage'; // Direct owner always has manage

    const userAccess = await env.DB.prepare(
        `SELECT permission_level FROM vault_access_controls
         WHERE vault_id = ? AND entity_id = ? AND entity_type = 'user'`
    ).bind(vaultId, `user_${userId}`).first() as VaultAccessControl | null;
    if (userAccess) return userAccess.permission_level;

    const orgAccess = await env.DB.prepare(
        `SELECT vac.permission_level
         FROM vault_access_controls vac
         JOIN user_organizations uo ON vac.entity_id = 'org_' || uo.organization_id AND vac.entity_type = 'organization'
         WHERE vac.vault_id = ? AND uo.user_id = ?`
    ).bind(vaultId, userId).first() as VaultAccessControl | null;
    return orgAccess ? orgAccess.permission_level : null;
}

export const JWT_EXPIRATION_TIME = '1h';

/**
 * Middleware to authenticate requests using JWT.
 * Attaches decoded user info to request.user.
 */
export async function authenticateRequest(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response | null> {
    const authHeader = request.headers.get('Authorization');
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logAudit(env, ctx, null, 'AUTH_FAILURE', { reason: 'No token' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized: No token provided." }, 401);
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = verify(token, env.JWT_SECRET) as { userId?: number; email: string; scope?: string; iat: number; exp: number };
        // Reject the short-lived token minted for the 2FA step (scope:'2fa',
        // carries `sub` not `userId`) — it must never authorize protected routes.
        if (decoded.scope === '2fa' || typeof decoded.userId !== 'number') {
            logAudit(env, ctx, null, 'AUTH_FAILURE', { reason: 'Non-session token' }, ipAddress, userAgent);
            return jsonResponse({ message: "Unauthorized: Invalid or expired token." }, 401);
        }
        request.user = decoded as { userId: number; email: string; iat: number; exp: number };
        return null; // Continue to the next handler/middleware
    } catch (error: any) {
        console.error("JWT verification failed:", error);
        logAudit(env, ctx, null, 'AUTH_FAILURE', { reason: 'Invalid/Expired token', error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized: Invalid or expired token." }, 401);
    }
}

/**
 * Middleware to check user's permission for a specific vault.
 * Requires `request.user` to be set by `authenticateRequest`.
 */
export async function checkVaultPermission(
    request: CustomRequest,
    env: Env,
    requiredPermission: 'read' | 'write' | 'manage',
    ctx: ExecutionContext
): Promise<Response | null> {
    const vaultIdParam = request.params?.vaultId;
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!vaultIdParam || !user || !user.userId) {
        logAudit(env, ctx, user?.userId || null, 'PERMISSION_CHECK_FAILURE', { vaultId: vaultIdParam, reason: 'Missing vaultId or user context' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized: Missing vault ID or user context." }, 401);
    }

    const vaultId = parseId(vaultIdParam);
    if (vaultId === null) {
        logAudit(env, ctx, user.userId, 'PERMISSION_CHECK_FAILURE', { vaultId: vaultIdParam, reason: 'Invalid vaultId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);
    }

    try {
        const accessLevel = await resolveVaultAccess(env, user.userId, vaultId);

        if (!accessLevel) {
            logAudit(env, ctx, user.userId, 'VAULT_ACCESS_DENIED', { vaultId, reason: 'No explicit access or ownership' }, ipAddress, userAgent);
            return jsonResponse({ message: "Forbidden: No access to this vault." }, 403);
        }

        if (!permissionSatisfies(accessLevel, requiredPermission)) {
            logAudit(env, ctx, user.userId, 'VAULT_ACCESS_DENIED', { vaultId, reason: 'Insufficient permission', required: requiredPermission, has: accessLevel }, ipAddress, userAgent);
            return jsonResponse({ message: `Forbidden: Insufficient permissions. Required: ${requiredPermission}, Has: ${accessLevel}` }, 403);
        }
        return null; // Permission granted, continue
    } catch (error: any) {
        console.error("Error checking vault permissions:", error);
        logAudit(env, ctx, user.userId, 'PERMISSION_CHECK_ERROR', { vaultId, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error during permission check." }, 500);
    }
}
