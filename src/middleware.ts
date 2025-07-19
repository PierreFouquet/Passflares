// src/middleware.ts

import { verify } from 'jsonwebtoken';
import { logAudit } from './auditLog.js'; // Ensure correct path and .js extension
import { CustomRequest, Env, VaultAccessControl, VaultMetadata } from './types.js'; // Ensure correct path and .js extension
import { jsonResponse } from './utils.js'; // Ensure correct path and .js extension

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
        const decoded = verify(token, env.JWT_SECRET) as { userId: number; email: string; iat: number; exp: number };
        request.user = decoded;
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

    const vaultId = parseInt(vaultIdParam);
    if (isNaN(vaultId)) {
        logAudit(env, ctx, user.userId, 'PERMISSION_CHECK_FAILURE', { vaultId: vaultIdParam, reason: 'Invalid vaultId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);
    }

    try {
        // Check if user is the direct owner (owner_type = 'user')
        const directOwnerCheck: { id: number } | null = await env.DB.prepare(
            "SELECT id FROM vaults WHERE id = ? AND owner_id = ? AND owner_type = 'user'"
        ).bind(vaultId, `user_${user.userId}`).first();

        let accessLevel: 'read' | 'write' | 'manage' | null = null;

        if (directOwnerCheck) {
            accessLevel = 'manage'; // Direct owner always has manage
        } else {
            // Check direct user access control
            const userAccess: VaultAccessControl | null = await env.DB.prepare(
                `SELECT permission_level FROM vault_access_controls
                 WHERE vault_id = ? AND entity_id = ? AND entity_type = 'user'`
            )
                .bind(vaultId, `user_${user.userId}`)
                .first() as VaultAccessControl | null;

            if (userAccess) {
                accessLevel = userAccess.permission_level;
            } else {
                // Check organizational access
                const orgAccess: VaultAccessControl | null = await env.DB.prepare(
                    `SELECT vac.permission_level
                     FROM vault_access_controls vac
                     JOIN user_organizations uo ON vac.entity_id = 'org_' || uo.organization_id AND vac.entity_type = 'organization'
                     WHERE vac.vault_id = ? AND uo.user_id = ?`
                )
                    .bind(vaultId, user.userId)
                    .first() as VaultAccessControl | null;

                if (orgAccess) {
                    accessLevel = orgAccess.permission_level;
                }
            }
        }

        if (!accessLevel) {
            logAudit(env, ctx, user.userId, 'VAULT_ACCESS_DENIED', { vaultId, reason: 'No explicit access or ownership' }, ipAddress, userAgent);
            return jsonResponse({ message: "Forbidden: No access to this vault." }, 403);
        }

        const permissionMap = { 'read': 1, 'write': 2, 'manage': 3 };

        if (permissionMap[accessLevel] < permissionMap[requiredPermission]) {
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
