// Tests for the audit-log subsystem (#73).
//
// Three defects, one per describe block:
//   1. Writes were floating promises — `logAudit` was async, ~120 call sites,
//      none awaited, none registered with ctx.waitUntil. Workers may cancel
//      pending I/O once the response is returned, so the events on fast-return
//      paths (LOGIN_FAILURE, AUTH_FAILURE, VAULT_ACCESS_DENIED) were the most
//      likely to be lost — exactly the ones that reveal an attack.
//   2. No retention. A row per request, no TTL, no pruning, sharing D1's 10 GB
//      limit with the vault metadata the service needs to function.
//   3. No way to read it, despite README claiming otherwise.

import { describe, it, expect, vi } from 'vitest';
import { logAudit, pruneAuditLogs, readUserAuditLog, AUDIT_RETENTION_DAYS, AUDIT_PAGE_MAX } from '../../src/auditLog.js';
import { handleGetAuditLog } from '../../src/auditLogHandlers.js';
import { createMockDB, createMockEnv, makeRequest } from '../mocks/cloudflare.js';

/** An ExecutionContext that records what was registered, and lets us await it. */
function recordingCtx() {
    const registered: Promise<unknown>[] = [];
    return {
        ctx: {
            waitUntil: vi.fn((p: Promise<unknown>) => { registered.push(p); }),
            passThroughOnException: vi.fn()
        } as unknown as ExecutionContext,
        registered,
        settle: () => Promise.all(registered)
    };
}

/** A D1 mock that records every INSERT into audit_logs. */
function auditCapturingDB() {
    const rows: unknown[][] = [];
    return {
        rows,
        db: {
            prepare: vi.fn((sql: string) => ({
                bind: vi.fn((...args: unknown[]) => ({
                    run: vi.fn(async () => {
                        if (/INSERT INTO audit_logs/.test(sql)) rows.push(args);
                        return { success: true, meta: { last_row_id: 1, changes: 1 } };
                    }),
                    first: vi.fn(async () => null),
                    all: vi.fn(async () => ({ results: [], success: true }))
                }))
            })),
            batch: vi.fn(async () => []),
            exec: vi.fn(async () => ({ results: [], success: true }))
        } as unknown as D1Database
    };
}

describe('#73 — audit writes must not be dropped', () => {
    it('registers the write with ctx.waitUntil', () => {
        const { db } = auditCapturingDB();
        const { ctx, registered } = recordingCtx();

        logAudit(createMockEnv({ DB: db }) as any, ctx, 7, 'LOGIN_FAILURE', { reason: 'x' }, '203.0.113.1', 'UA');

        expect(ctx.waitUntil).toHaveBeenCalledTimes(1);
        expect(registered).toHaveLength(1);
    });

    // The whole point of the change: the caller does not have to remember
    // anything. A void return means there is no promise to drop.
    it('returns void, so no call site can leave a floating promise', () => {
        const { db } = auditCapturingDB();
        const { ctx } = recordingCtx();

        const result = logAudit(createMockEnv({ DB: db }) as any, ctx, 7, 'LOGIN_FAILURE', {}, null, null);
        expect(result).toBeUndefined();
    });

    it('actually performs the insert once the registered work settles', async () => {
        const { db, rows } = auditCapturingDB();
        const { ctx, settle } = recordingCtx();

        logAudit(createMockEnv({ DB: db }) as any, ctx, 42, 'VAULT_ACCESS_DENIED', { vaultId: 3 }, '203.0.113.5', 'UA');
        await settle();

        expect(rows).toHaveLength(1);
        const [userId, action, payload, ip, ua] = rows[0];
        expect(userId).toBe(42);
        expect(action).toBe('VAULT_ACCESS_DENIED');
        expect(JSON.parse(payload as string)).toEqual({ vaultId: 3 });
        expect(ip).toBe('203.0.113.5');
        expect(ua).toBe('UA');
    });

    // Audit logging must never break the request it is describing.
    it('swallows a database failure instead of rejecting', async () => {
        const failing = {
            prepare: () => ({ bind: () => ({ run: async () => { throw new Error('D1 down'); } }) })
        } as unknown as D1Database;
        const { ctx, settle } = recordingCtx();
        const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

        expect(() => logAudit({ DB: failing } as any, ctx, 1, 'X', {}, null, null)).not.toThrow();
        await expect(settle()).resolves.toBeDefined();
        expect(spy).toHaveBeenCalled();
        spy.mockRestore();
    });
});

describe('#73 — retention', () => {
    it('deletes only rows older than the retention window', async () => {
        let boundCutoff: string | undefined;
        const db = {
            prepare: vi.fn((sql: string) => {
                expect(sql).toMatch(/DELETE FROM audit_logs/);
                return {
                    bind: vi.fn((cutoff: string, _limit: number) => {
                        boundCutoff = cutoff;
                        return { run: vi.fn(async () => ({ success: true, meta: { changes: 17 } })) };
                    })
                };
            })
        } as unknown as D1Database;

        const deleted = await pruneAuditLogs({ DB: db } as any);

        expect(deleted).toBe(17);
        const cutoffMs = Date.parse(boundCutoff!);
        const expected = Date.now() - AUDIT_RETENTION_DAYS * 24 * 60 * 60 * 1000;
        expect(Math.abs(cutoffMs - expected)).toBeLessThan(5000);
    });

    it('bounds each sweep so one cron run cannot exceed its budget', async () => {
        let limit: number | undefined;
        const db = {
            prepare: vi.fn((sql: string) => {
                // The bounded form is what makes a large backlog drain over
                // several runs rather than timing out on the first.
                expect(sql).toMatch(/LIMIT \?/);
                return {
                    bind: vi.fn((_cutoff: string, l: number) => {
                        limit = l;
                        return { run: vi.fn(async () => ({ success: true, meta: { changes: 0 } })) };
                    })
                };
            })
        } as unknown as D1Database;

        await pruneAuditLogs({ DB: db } as any);
        expect(limit).toBeGreaterThan(0);
        expect(limit).toBeLessThanOrEqual(10000);
    });
});

describe('#73 — the log is readable by the account that owns it', () => {
    const sampleRows = [
        { action: 'LOGIN_SUCCESS', payload: '{"email":"a@b.c"}', ip_address: '203.0.113.1', user_agent: 'UA', timestamp: '2026-08-01T10:00:00.000Z' },
        { action: 'LOGIN_FAILURE', payload: '{"reason":"Credential mismatch"}', ip_address: '198.51.100.9', user_agent: 'UA', timestamp: '2026-08-01T09:00:00.000Z' }
    ];

    function dbReturning(rows: unknown[]) {
        return createMockDB({ 'FROM audit_logs': { all: rows as any } });
    }

    function authedReq(path: string, userId = 5) {
        const req = makeRequest('GET', path) as any;
        req.user = { userId, email: 'a@b.c' };
        return req;
    }

    it('returns the caller’s events, newest first, with the payload parsed', async () => {
        const events = await readUserAuditLog({ DB: dbReturning(sampleRows) } as any, 5, 50, null);

        expect(events).toHaveLength(2);
        expect(events[0].action).toBe('LOGIN_SUCCESS');
        expect(events[0].detail).toEqual({ email: 'a@b.c' });
        expect(events[1].ipAddress).toBe('198.51.100.9');
    });

    it('scopes the query to the caller — never another account', async () => {
        let bound: unknown[] = [];
        const db = {
            prepare: vi.fn((sql: string) => {
                expect(sql).toMatch(/WHERE user_id = \?/);
                return { bind: vi.fn((...a: unknown[]) => { bound = a; return { all: vi.fn(async () => ({ results: [], success: true })) }; }) };
            })
        } as unknown as D1Database;

        await readUserAuditLog({ DB: db } as any, 5, 50, null);
        expect(bound[0]).toBe(5);
    });

    it('survives a payload that is not valid JSON', async () => {
        const events = await readUserAuditLog(
            { DB: dbReturning([{ ...sampleRows[0], payload: 'not json{' }]) } as any, 5, 50, null
        );
        expect(events[0].detail).toEqual({});
    });

    it('caps the page size no matter what the caller asks for', async () => {
        let limit: unknown;
        const db = {
            prepare: vi.fn(() => ({
                bind: vi.fn((_u: number, l: number) => { limit = l; return { all: vi.fn(async () => ({ results: [], success: true })) }; })
            }))
        } as unknown as D1Database;

        await readUserAuditLog({ DB: db } as any, 5, 100000, null);
        expect(limit).toBe(AUDIT_PAGE_MAX);
    });

    it('serves a page over HTTP with a keyset cursor', async () => {
        const env = createMockEnv({ DB: dbReturning(sampleRows) });
        const res = await handleGetAuditLog(authedReq('/api/users/me/audit-log?limit=2'), env as any, {} as any);

        expect(res.status).toBe(200);
        const body = await res.json() as any;
        expect(body.events).toHaveLength(2);
        // A full page hands back the last timestamp so the next call can resume.
        expect(body.nextBefore).toBe('2026-08-01T09:00:00.000Z');
        expect(body.retentionDays).toBe(AUDIT_RETENTION_DAYS);
    });

    it('reports the end of the log with a null cursor', async () => {
        const env = createMockEnv({ DB: dbReturning(sampleRows) });
        const res = await handleGetAuditLog(authedReq('/api/users/me/audit-log?limit=50'), env as any, {} as any);
        expect((await res.json() as any).nextBefore).toBeNull();
    });

    it('rejects a nonsense limit rather than silently clamping', async () => {
        const env = createMockEnv({ DB: dbReturning([]) });
        for (const q of ['limit=0', 'limit=-1', 'limit=abc', `limit=${AUDIT_PAGE_MAX + 1}`]) {
            const res = await handleGetAuditLog(authedReq(`/api/users/me/audit-log?${q}`), env as any, {} as any);
            expect(res.status, q).toBe(400);
        }
    });

    // A malformed cursor would otherwise return an empty page, which reads as
    // "nothing has happened on your account" — the opposite of the truth.
    it('rejects a malformed before cursor', async () => {
        const env = createMockEnv({ DB: dbReturning([]) });
        const res = await handleGetAuditLog(authedReq('/api/users/me/audit-log?before=yesterday'), env as any, {} as any);
        expect(res.status).toBe(400);
    });

    it('accepts the cursor shape it produces', async () => {
        const env = createMockEnv({ DB: dbReturning([]) });
        const res = await handleGetAuditLog(
            authedReq('/api/users/me/audit-log?before=2026-08-01T09:00:00.000Z'), env as any, {} as any
        );
        expect(res.status).toBe(200);
    });
});
