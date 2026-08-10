// resolveVaultAccess / checkVaultPermission against real SQLite (#89 §6, #83 §1).
//
// This is the function #83 opened with. Its unit tests in
// tests/backend/middleware.test.ts drive it through the substring-matching mock,
// which returns the same canned row whatever is bound — so a test called
// "returns null when user is the direct owner of the vault" passes even if the
// query drops `AND owner_id = ?`, compares the wrong user, or ignores the vault
// id entirely. It proves the TypeScript branching, not the authorization.
//
// Measured rather than assumed: with the falsifiability gate pointed at
// middleware.test.ts alone, all three SQL-scoping mutants (mw-owner-any-vault,
// mw-acl-any-user, mw-org-any-member) SURVIVE. They are killed today only
// because unrelated suites happen to exercise the same code against real SQL.
//
// So the scoping is asserted here, where bound parameters decide the answer and
// the assertions sit under the function's own name. Every test below turns on
// "the right row exists but belongs to somebody else, or to another vault".

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createTestD1, createTestR2, type TestD1 } from '../../mocks/d1.js';
import { createMockRateLimiter, mockCtx } from '../../mocks/cloudflare.js';

vi.mock('../../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

const { resolveVaultAccess, checkVaultPermission, permissionSatisfies } =
    await import('../../../src/middleware.js');

let d1: TestD1;
let env: any;

beforeEach(() => {
    d1 = createTestD1();
    env = {
        DB: d1,
        VAULTS: createTestR2(),
        RATE_LIMITER: createMockRateLimiter(),
        JWT_SECRET: 'test-jwt-secret-32-chars-minimum!!'
    };
});

function addUser(email: string): number {
    const info = d1.db.prepare(
        `INSERT INTO users (email, password_hash, password_salt, encryption_salt, auth_version)
         VALUES (?, 'h', 's', '', 2)`
    ).run(email);
    return Number(info.lastInsertRowid);
}

function addVault(ownerId: string, ownerType: 'user' | 'organization', name = 'Vault'): number {
    const info = d1.db.prepare(
        `INSERT INTO vaults (name, owner_id, owner_type, r2_object_key)
         VALUES (?, ?, ?, ?)`
    ).run(name, ownerId, ownerType, `vaults/${ownerId}-${name}-${Math.floor(performance.now() * 1000)}`);
    return Number(info.lastInsertRowid);
}

function grant(vaultId: number, entityId: string, entityType: 'user' | 'organization', level: string): void {
    d1.db.prepare(
        `INSERT INTO vault_access_controls (vault_id, entity_id, entity_type, permission_level)
         VALUES (?, ?, ?, ?)`
    ).run(vaultId, entityId, entityType, level);
}

function addOrg(name: string, createdBy: number): number {
    const info = d1.db.prepare('INSERT INTO organizations (name, created_by) VALUES (?, ?)')
        .run(name, createdBy);
    return Number(info.lastInsertRowid);
}

function addMember(userId: number, orgId: number, role = 'member'): void {
    d1.db.prepare('INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, ?)')
        .run(userId, orgId, role);
}

/** A request shaped the way the router hands one to checkVaultPermission. */
function authed(userId: number, vaultId: number | string): any {
    const req: any = new Request(`https://example.com/api/vaults/${vaultId}/data`);
    req.params = { vaultId: String(vaultId) };
    req.user = { userId, email: `u${userId}@example.com`, iat: 0, exp: 9_999_999_999 };
    return req;
}

describe('direct ownership is scoped to both the vault and the owner', () => {
    it('grants manage to the owner of that specific vault', async () => {
        const alice = addUser('alice@example.com');
        const vault = addVault(`user_${alice}`, 'user');

        expect(await resolveVaultAccess(env, alice, vault)).toBe('manage');
    });

    it('does not leak one user’s vault to another user', async () => {
        // mw-acl-any-user / mw-owner-any-vault: with owner_id unbound, Bob
        // resolves to manage on Alice's vault.
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        const aliceVault = addVault(`user_${alice}`, 'user', 'Alice');

        expect(await resolveVaultAccess(env, bob, aliceVault)).toBeNull();
    });

    it('does not grant access to a different vault the same user does not own', async () => {
        // mw-owner-any-vault: dropping `id = ?` makes ownership of *any* vault
        // grant manage on *every* vault. Alice owns one and not the other, so
        // only a query scoped to the requested id can tell them apart.
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        addVault(`user_${alice}`, 'user', 'Owned');
        const bobVault = addVault(`user_${bob}`, 'user', 'NotHers');

        expect(await resolveVaultAccess(env, alice, bobVault)).toBeNull();
    });

    it('does not treat an organisation-owned vault as directly owned', async () => {
        // owner_type is part of the predicate: 'org_3' must not match user 3.
        const carol = addUser('carol@example.com');
        const org = addOrg('Acme', carol);
        const orgVault = addVault(`org_${org}`, 'organization');

        // No org ACL row yet, so membership alone grants nothing.
        addMember(carol, org);
        expect(await resolveVaultAccess(env, carol, orgVault)).toBeNull();
    });
});

describe('explicit user grants are scoped to the grantee', () => {
    it('returns the level recorded for that user', async () => {
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        const vault = addVault(`user_${alice}`, 'user');
        grant(vault, `user_${bob}`, 'user', 'write');

        expect(await resolveVaultAccess(env, bob, vault)).toBe('write');
    });

    it('does not hand one grantee’s access to a different user', async () => {
        // mw-acl-any-user: unbind entity_id and Carol inherits Bob's grant.
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        const carol = addUser('carol@example.com');
        const vault = addVault(`user_${alice}`, 'user');
        grant(vault, `user_${bob}`, 'user', 'manage');

        expect(await resolveVaultAccess(env, carol, vault)).toBeNull();
    });

    it('does not carry a grant on one vault across to another', async () => {
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        const shared = addVault(`user_${alice}`, 'user', 'Shared');
        const private_ = addVault(`user_${alice}`, 'user', 'Private');
        grant(shared, `user_${bob}`, 'user', 'read');

        expect(await resolveVaultAccess(env, bob, shared)).toBe('read');
        expect(await resolveVaultAccess(env, bob, private_)).toBeNull();
    });
});

describe('organisation grants are scoped to actual membership', () => {
    it('grants a member the organisation’s level on the vault', async () => {
        const owner = addUser('owner@example.com');
        const member = addUser('member@example.com');
        const org = addOrg('Acme', owner);
        addMember(member, org);
        const vault = addVault(`org_${org}`, 'organization');
        grant(vault, `org_${org}`, 'organization', 'write');

        expect(await resolveVaultAccess(env, member, vault)).toBe('write');
    });

    it('refuses a user who is not in the organisation', async () => {
        // mw-org-any-member: unbind uo.user_id and any outsider joins the JOIN.
        const owner = addUser('owner@example.com');
        const member = addUser('member@example.com');
        const outsider = addUser('outsider@example.com');
        const org = addOrg('Acme', owner);
        addMember(member, org);
        const vault = addVault(`org_${org}`, 'organization');
        grant(vault, `org_${org}`, 'organization', 'manage');

        expect(await resolveVaultAccess(env, member, vault)).toBe('manage');
        expect(await resolveVaultAccess(env, outsider, vault)).toBeNull();
    });

    it('does not let membership of one organisation open another’s vault', async () => {
        // The JOIN builds 'org_' || uo.organization_id, so a member of org A
        // must not match a grant naming org B.
        const owner = addUser('owner@example.com');
        const user = addUser('user@example.com');
        const orgA = addOrg('Acme', owner);
        const orgB = addOrg('Globex', owner);
        addMember(user, orgA);
        const vaultB = addVault(`org_${orgB}`, 'organization');
        grant(vaultB, `org_${orgB}`, 'organization', 'manage');

        expect(await resolveVaultAccess(env, user, vaultB)).toBeNull();
    });

    it('returns null — not manage — when there is no grant of any kind', async () => {
        // mw-no-access-grants-manage: the fallback must deny, and the only way
        // to see that is a database where none of the three queries match.
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        const vault = addVault(`user_${alice}`, 'user');

        expect(await resolveVaultAccess(env, bob, vault)).toBeNull();
    });
});

describe('checkVaultPermission enforces the ranking over real rows', () => {
    it('lets read satisfy read but not write or manage', async () => {
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        const vault = addVault(`user_${alice}`, 'user');
        grant(vault, `user_${bob}`, 'user', 'read');

        expect(await checkVaultPermission(authed(bob, vault), env, 'read', mockCtx)).toBeNull();
        expect((await checkVaultPermission(authed(bob, vault), env, 'write', mockCtx))!.status).toBe(403);
        expect((await checkVaultPermission(authed(bob, vault), env, 'manage', mockCtx))!.status).toBe(403);
    });

    it('lets write satisfy read and write but not manage', async () => {
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        const vault = addVault(`user_${alice}`, 'user');
        grant(vault, `user_${bob}`, 'user', 'write');

        expect(await checkVaultPermission(authed(bob, vault), env, 'read', mockCtx)).toBeNull();
        expect(await checkVaultPermission(authed(bob, vault), env, 'write', mockCtx)).toBeNull();
        expect((await checkVaultPermission(authed(bob, vault), env, 'manage', mockCtx))!.status).toBe(403);
    });

    it('lets the owner do everything', async () => {
        const alice = addUser('alice@example.com');
        const vault = addVault(`user_${alice}`, 'user');

        for (const level of ['read', 'write', 'manage'] as const) {
            expect(await checkVaultPermission(authed(alice, vault), env, level, mockCtx)).toBeNull();
        }
    });

    it('403s a stranger on every level', async () => {
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        const vault = addVault(`user_${alice}`, 'user');

        for (const level of ['read', 'write', 'manage'] as const) {
            expect((await checkVaultPermission(authed(bob, vault), env, level, mockCtx))!.status).toBe(403);
        }
    });

    it('403s on a vault that does not exist at all', async () => {
        const alice = addUser('alice@example.com');
        expect((await checkVaultPermission(authed(alice, 9999), env, 'read', mockCtx))!.status).toBe(403);
    });

    it('ranks the three levels in the documented order', () => {
        // mw-perm-inverted / mw-perm-always-ok. Cheap, but it is the whole
        // ordering stated in one place rather than implied by the cases above.
        expect(permissionSatisfies('manage', 'write')).toBe(true);
        expect(permissionSatisfies('write', 'read')).toBe(true);
        expect(permissionSatisfies('read', 'write')).toBe(false);
        expect(permissionSatisfies('write', 'manage')).toBe(false);
        expect(permissionSatisfies('read', 'read')).toBe(true);
    });
});
