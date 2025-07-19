// src/auditLog.ts

import { Env, AuditLogEntry } from './types.js'; // Ensure correct path and .js extension

/**
 * Logs an audit event to the D1 database.
 * @param env Cloudflare Worker environment.
 * @param ctx ExecutionContext.
 * @param userId The ID of the user performing the action (null if unauthenticated).
 * @param action The type of action (e.g., 'LOGIN', 'VAULT_CREATE', 'AUTH_FAILURE').
 * @param payload An object containing details of the action.
 * @param ipAddress IP address of the requester (from CF-Connecting-IP header).
 * @param userAgent User-Agent string of the requester.
 */
export async function logAudit(
    env: Env,
    ctx: ExecutionContext,
    userId: number | null,
    action: string,
    payload: Record<string, any>,
    ipAddress: string | null,
    userAgent: string | null
): Promise<void> {
    const timestamp = new Date().toISOString();
    const payloadJson = JSON.stringify(payload);

    try {
        await env.DB.prepare(
            `INSERT INTO audit_logs (user_id, action, payload, ip_address, user_agent, timestamp)
             VALUES (?, ?, ?, ?, ?, ?)`
        )
            .bind(userId, action, payloadJson, ipAddress, userAgent, timestamp)
            .run();
    } catch (error) {
        console.error("Failed to log audit event:", error);
        // Do not throw, as audit logging should not break the main request flow
    }
}
