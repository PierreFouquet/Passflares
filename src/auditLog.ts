// src/auditLog.ts

import { Env, AuditLogEntry } from './types.js'; // Ensure correct path and .js extension

/**
 * How long an audit row is kept. Swept by the scheduled handler in worker.ts.
 *
 * The table previously had no retention at all and shares its 10 GB D1 limit
 * with vault metadata and user records, so unbounded audit growth was on course
 * to threaten the functional data (#73).
 */
export const AUDIT_RETENTION_DAYS = 90;

/** Rows deleted per sweep. Bounded so one cron invocation stays inside its CPU budget. */
const PRUNE_BATCH = 5000;

/** Page-size ceiling for the self-service read endpoint. */
export const AUDIT_PAGE_MAX = 100;

/**
 * Records an audit event.
 *
 * Deliberately **not** `async`. It used to be, and none of its ~120 call sites
 * awaited it — in Workers, I/O started during a request but never registered
 * with `ctx.waitUntil()` is not guaranteed to run once the response is returned.
 * The events most likely to be lost were the ones on fast-return paths
 * (`LOGIN_FAILURE`, `AUTH_FAILURE`, `VAULT_ACCESS_DENIED`), which is precisely
 * the set that reveals an attack in progress (#73).
 *
 * Returning `void` rather than a promise is the point: there is nothing for a
 * caller to forget to await, and `code-security-invariants.test.ts` fails the
 * build if anyone reintroduces a bare `env.DB … audit_logs` write elsewhere.
 *
 * @param env Cloudflare Worker environment.
 * @param ctx ExecutionContext — the write is registered against it.
 * @param userId The ID of the user performing the action (null if unauthenticated).
 * @param action The type of action (e.g., 'LOGIN', 'VAULT_CREATE', 'AUTH_FAILURE').
 * @param payload An object containing details of the action.
 * @param ipAddress IP address of the requester (from CF-Connecting-IP header).
 * @param userAgent User-Agent string of the requester.
 */
export function logAudit(
    env: Env,
    ctx: ExecutionContext,
    userId: number | null,
    action: string,
    payload: Record<string, any>,
    ipAddress: string | null,
    userAgent: string | null
): void {
    const write = env.DB.prepare(
        `INSERT INTO audit_logs (user_id, action, payload, ip_address, user_agent, timestamp)
         VALUES (?, ?, ?, ?, ?, ?)`
    )
        .bind(userId, action, JSON.stringify(payload), ipAddress, userAgent, new Date().toISOString())
        .run()
        // Audit logging must never break the main request flow — and by the time
        // this settles the response has usually already been returned.
        .catch((error: unknown) => console.error('Failed to log audit event:', error));

    ctx.waitUntil(write);
}

/**
 * Deletes audit rows past the retention window. Driven by the cron trigger in
 * wrangler.toml.
 *
 * The `id IN (SELECT … LIMIT)` form bounds the work per invocation, so a large
 * backlog drains over successive runs instead of timing out on the first.
 * Relies on `idx_audit_time` (migrations/0006) to avoid a full table scan.
 *
 * @returns the number of rows deleted.
 */
export async function pruneAuditLogs(env: Env, retentionDays = AUDIT_RETENTION_DAYS): Promise<number> {
    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
    const result = await env.DB.prepare(
        `DELETE FROM audit_logs WHERE id IN
             (SELECT id FROM audit_logs WHERE timestamp < ? ORDER BY timestamp LIMIT ?)`
    ).bind(cutoff, PRUNE_BATCH).run();
    return result.meta?.changes ?? 0;
}

/** One event as returned to the account that owns it. */
export interface AuditLogView {
    action: string;
    timestamp: string;
    ipAddress: string | null;
    userAgent: string | null;
    detail: Record<string, any>;
}

/**
 * The caller's own audit events, newest first.
 *
 * Keyset pagination on `timestamp` rather than OFFSET: an offset re-scans every
 * skipped row, and rows arriving between pages shift the window. Uses
 * `idx_audit_user_time`.
 */
export async function readUserAuditLog(
    env: Env,
    userId: number,
    limit: number,
    before: string | null
): Promise<AuditLogView[]> {
    const capped = Math.min(Math.max(limit, 1), AUDIT_PAGE_MAX);
    // Two static statements rather than one built conditionally — .prepare()
    // must take a literal string, which code-security-invariants.test.ts enforces.
    const rows = before
        ? await env.DB.prepare(
            `SELECT action, payload, ip_address, user_agent, timestamp FROM audit_logs
             WHERE user_id = ? AND timestamp < ? ORDER BY timestamp DESC LIMIT ?`
        ).bind(userId, before, capped).all()
        : await env.DB.prepare(
            `SELECT action, payload, ip_address, user_agent, timestamp FROM audit_logs
             WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?`
        ).bind(userId, capped).all();

    return (rows.results as unknown as AuditLogEntry[]).map(row => ({
        action: row.action,
        timestamp: row.timestamp,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        detail: safeParsePayload(row.payload)
    }));
}

/** A truncated or pre-schema-change row must not 500 the whole page. */
function safeParsePayload(payload: string): Record<string, any> {
    try {
        const parsed = JSON.parse(payload);
        return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch {
        return {};
    }
}
