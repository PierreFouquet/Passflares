// src/auditLogHandlers.ts
//
// The read side of the audit log (#73).
//
// README claimed audit events were "available to admins", but no read path
// existed at all — `auditLog.ts` exported only the writer, no route touched the
// table, and the only way to see the data was `wrangler d1 execute`.
//
// This exposes each account's own events rather than building a global admin
// role. The session token already scopes the query to one user, so there is no
// new privilege surface on a service whose whole premise is that the operator
// cannot read user data.

import { CustomRequest, Env } from './types.js';
import { jsonResponse } from './utils.js';
import { readUserAuditLog, AUDIT_PAGE_MAX, AUDIT_RETENTION_DAYS } from './auditLog.js';

const DEFAULT_PAGE = 50;

/** ISO-8601, as written by `new Date().toISOString()` in logAudit. */
const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * GET /api/users/me/audit-log?limit=&before=
 *
 * `before` is the previous page's `nextBefore` — keyset pagination, so pages
 * stay stable as new events arrive.
 */
export async function handleGetAuditLog(request: CustomRequest, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const userId = request.user!.userId;
    const url = new URL(request.url);

    const limitParam = url.searchParams.get('limit');
    const limit = limitParam === null ? DEFAULT_PAGE : Number(limitParam);
    if (!Number.isInteger(limit) || limit < 1 || limit > AUDIT_PAGE_MAX) {
        return jsonResponse({ message: `limit must be an integer between 1 and ${AUDIT_PAGE_MAX}.` }, 400);
    }

    // Validated rather than passed through: it is bound as a parameter so it is
    // not injectable, but a garbage value would silently return an empty page,
    // which reads as "nothing happened on your account" — the opposite of what
    // this endpoint exists to tell someone.
    const before = url.searchParams.get('before');
    if (before !== null && !ISO_TIMESTAMP_RE.test(before)) {
        return jsonResponse({ message: 'before must be an ISO-8601 timestamp.' }, 400);
    }

    try {
        const events = await readUserAuditLog(env, userId, limit, before);
        return jsonResponse({
            events,
            // Absent when the page is short, which is how the client knows it
            // has reached the end without issuing one more empty request.
            nextBefore: events.length === limit ? events[events.length - 1].timestamp : null,
            retentionDays: AUDIT_RETENTION_DAYS
        });
    } catch (error: any) {
        console.error('Get audit log error:', error);
        return jsonResponse({ message: 'Internal Server Error.' }, 500);
    }
}
