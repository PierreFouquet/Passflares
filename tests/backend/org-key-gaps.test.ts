// GET /api/organizations/:orgId/key-gaps — the server half of organisation
// vault-key reconciliation (#69 residue).
//
// The bug: key shares were wrapped exactly once, at the instant a member was
// added. Any wrap that was impossible right then never happened at all — most
// commonly because the member had never signed in and so had no keypair to wrap
// to. They stayed permanently locked out of vaults they were entitled to.
//
// This endpoint reports those gaps so a client that holds the key can close
// them. It must report entitlement only, never key material.

import { describe, it, expect, vi } from 'vitest';
import { handleGetOrgKeyGaps } from '../../src/organizations.js';
import { createMockEnv, mockCtx } from '../mocks/cloudflare.js';

vi.mock('../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

type GapRow = {
    vaultId: number; vaultName: string; userId: number; email: string; publicKey: string | null;
};

/** D1 stub: one membership lookup, then the anti-join that finds the gaps. */
function makeDB(membership: { role: string } | null, rows: GapRow[], onBind?: (a: unknown[]) => void) {
    return {
        prepare: vi.fn((sql: string) => ({
            bind: vi.fn((...args: unknown[]) => {
                onBind?.(args);
                return {
                    first: vi.fn(async () =>
                        /FROM user_organizations WHERE user_id/.test(sql) ? membership : null),
                    all: vi.fn(async () => ({ results: rows, success: true })),
                    run: vi.fn(async () => ({ success: true, meta: { changes: 0 } }))
                };
            })
        })),
        batch: vi.fn(async () => [])
    } as unknown as D1Database;
}

function req(orgId = '7', userId = 1) {
    const r: any = new Request('https://passflares.com/api/organizations/7/key-gaps');
    r.user = { userId, email: 'admin@example.com' };
    r.params = { orgId };
    return r;
}

const MEMBER = { role: 'member' };

describe('GET /api/organizations/:orgId/key-gaps', () => {
    it('groups missing members by vault', async () => {
        const env = createMockEnv({
            DB: makeDB(MEMBER, [
                { vaultId: 3, vaultName: 'Ops', userId: 5, email: 'a@x.co', publicKey: 'PUB_A' },
                { vaultId: 3, vaultName: 'Ops', userId: 6, email: 'b@x.co', publicKey: 'PUB_B' },
                { vaultId: 9, vaultName: 'Finance', userId: 5, email: 'a@x.co', publicKey: 'PUB_A' }
            ])
        });

        const body = await (await handleGetOrgKeyGaps(req(), env as any, mockCtx)).json() as any;

        expect(body.gaps).toHaveLength(2);
        const ops = body.gaps.find((g: any) => g.vaultId === 3);
        expect(ops.vaultName).toBe('Ops');
        expect(ops.missing.map((m: any) => m.userId)).toEqual([5, 6]);
        expect(body.gaps.find((g: any) => g.vaultId === 9).missing).toHaveLength(1);
    });

    // The distinction that matters operationally: one is an admin's job, the
    // other can only be resolved by the member signing in.
    it('separates members with no keypair from members awaiting a wrap', async () => {
        const env = createMockEnv({
            DB: makeDB(MEMBER, [
                { vaultId: 3, vaultName: 'Ops', userId: 5, email: 'ready@x.co', publicKey: 'PUB_A' },
                { vaultId: 3, vaultName: 'Ops', userId: 6, email: 'never-signed-in@x.co', publicKey: null }
            ])
        });

        const gap = (await (await handleGetOrgKeyGaps(req(), env as any, mockCtx)).json() as any).gaps[0];

        expect(gap.missing.map((m: any) => m.email)).toEqual(['ready@x.co']);
        expect(gap.notUpgraded.map((m: any) => m.email)).toEqual(['never-signed-in@x.co']);
    });

    it('returns the public key, so the client can wrap without another round trip', async () => {
        const env = createMockEnv({
            DB: makeDB(MEMBER, [{ vaultId: 3, vaultName: 'Ops', userId: 5, email: 'a@x.co', publicKey: 'PUB_A' }])
        });
        const body = await (await handleGetOrgKeyGaps(req(), env as any, mockCtx)).json() as any;
        expect(body.gaps[0].missing[0].publicKey).toBe('PUB_A');
    });

    // A wrapped key is only openable by its recipient, but this endpoint has no
    // business carrying one — it reports entitlement, nothing else.
    it('never returns key material', async () => {
        const env = createMockEnv({
            DB: makeDB(MEMBER, [{ vaultId: 3, vaultName: 'Ops', userId: 5, email: 'a@x.co', publicKey: 'PUB_A' }])
        });
        const raw = await (await handleGetOrgKeyGaps(req(), env as any, mockCtx)).text();
        expect(raw).not.toMatch(/wrapped_key|wrappedKey|private_key|privateKey|ephemeral/i);
    });

    it('is empty when everyone already holds every key', async () => {
        const env = createMockEnv({ DB: makeDB(MEMBER, []) });
        const body = await (await handleGetOrgKeyGaps(req(), env as any, mockCtx)).json() as any;
        expect(body.gaps).toEqual([]);
    });

    it('refuses a non-member', async () => {
        const env = createMockEnv({ DB: makeDB(null, []) });
        const res = await handleGetOrgKeyGaps(req(), env as any, mockCtx);
        expect(res.status).toBe(403);
    });

    // Convergence must not depend on one specific person being available — that
    // dependency is what left members stranded in the first place.
    it('serves plain members, not just admins', async () => {
        const env = createMockEnv({
            DB: makeDB({ role: 'member' }, [
                { vaultId: 3, vaultName: 'Ops', userId: 5, email: 'a@x.co', publicKey: 'PUB_A' }
            ])
        });
        const res = await handleGetOrgKeyGaps(req(), env as any, mockCtx);
        expect(res.status).toBe(200);
        expect(((await res.json()) as any).gaps).toHaveLength(1);
    });

    it('rejects a malformed organisation id', async () => {
        const env = createMockEnv({ DB: makeDB(MEMBER, []) });
        const res = await handleGetOrgKeyGaps(req('not-a-number'), env as any, mockCtx);
        expect(res.status).toBe(400);
    });

    it('scopes the query to the requested organisation', async () => {
        const bound: unknown[][] = [];
        const env = createMockEnv({ DB: makeDB(MEMBER, [], a => bound.push(a)) });
        await handleGetOrgKeyGaps(req('7'), env as any, mockCtx);
        // Membership check binds (userId, orgId); the anti-join binds (orgId, orgId).
        expect(bound.some(a => a.length === 2 && a[0] === 7 && a[1] === 7)).toBe(true);
    });

    it('answers 500 rather than leaking an exception on a DB failure', async () => {
        const env = createMockEnv({
            DB: { prepare: () => { throw new Error('D1 exploded: table vault_key_shares'); } } as unknown as D1Database
        });
        const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const res = await handleGetOrgKeyGaps(req(), env as any, mockCtx);
        expect(res.status).toBe(500);
        expect(await res.text()).not.toMatch(/D1 exploded/);
        spy.mockRestore();
    });
});
