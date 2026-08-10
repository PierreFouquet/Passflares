// Authorization tests against real SQLite, where bound parameters decide the
// result. The substring-matching mock in tests/mocks/cloudflare.ts returns the
// same canned row whatever is bound, so it cannot show that a query is scoped
// to the right account (#83).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createTestD1, createTestR2, type TestD1 } from '../../mocks/d1.js';
import { createMockRateLimiter, makeRequest, mockCtx } from '../../mocks/cloudflare.js';

vi.mock('../../../src/auditLog.js', () => ({ logAudit: vi.fn() }));

const { __testables } = await import('../../../src/totp.js');
const { handleUpdateMemberRole, handleRemoveMember } = await import('../../../src/organizations.js');
const { hashRecoveryCode, consumeRecoveryCode } = __testables;

let d1: TestD1;
let env: any;

beforeEach(() => {
    d1 = createTestD1();
    env = {
        DB: d1,
        VAULTS: createTestR2(),
        RATE_LIMITER: createMockRateLimiter(),
        JWT_SECRET: 'test-jwt-secret-32-chars-minimum!!',
        TURNSTILE_KEY: 'test-turnstile-key',
        TOTP_ENC_KEY: 'test-totp-enc-key-32-chars-minimum!!'
    };
});

function addUser(email: string): number {
    const info = d1.db.prepare(
        `INSERT INTO users (email, password_hash, password_salt, encryption_salt, auth_version)
         VALUES (?, 'h', 's', '', 2)`
    ).run(email);
    return Number(info.lastInsertRowid);
}

function addOrg(name: string, createdBy: number): number {
    const info = d1.db.prepare('INSERT INTO organizations (name, created_by) VALUES (?, ?)')
        .run(name, createdBy);
    return Number(info.lastInsertRowid);
}

function addMember(userId: number, orgId: number, role: string): void {
    d1.db.prepare('INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, ?)')
        .run(userId, orgId, role);
}

function giveRecoveryCode(userId: number, code: string): void {
    d1.db.prepare('INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)')
        .run(userId, hashRecoveryCode(env, code));
}

function roleOf(userId: number, orgId: number): string | null {
    const rows = d1.query<{ role: string }>(
        'SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?',
        userId, orgId
    );
    return rows.length ? rows[0].role : null;
}

/** An organisation-owned vault, with the ACL row that makes it reachable. */
function addOrgVault(orgId: number, name: string): number {
    const info = d1.db.prepare(
        `INSERT INTO vaults (name, owner_id, owner_type, r2_object_key)
         VALUES (?, ?, 'organization', ?)`
    ).run(name, `org_${orgId}`, `vaults/${orgId}-${name}`);
    const vaultId = Number(info.lastInsertRowid);
    d1.db.prepare(
        `INSERT INTO vault_access_controls (vault_id, entity_id, entity_type, permission_level)
         VALUES (?, ?, 'organization', 'write')`
    ).run(vaultId, `org_${orgId}`);
    return vaultId;
}

function giveKeyShare(vaultId: number, userId: number): void {
    d1.db.prepare(
        `INSERT INTO vault_key_shares (vault_id, user_id, wrapped_key, ephemeral_pubkey)
         VALUES (?, ?, 'iv:ct', 'pub')`
    ).run(vaultId, userId);
}

function shareHolders(vaultId: number): number[] {
    return d1.query<{ user_id: number }>(
        'SELECT user_id FROM vault_key_shares WHERE vault_id = ? ORDER BY user_id', vaultId
    ).map(r => r.user_id);
}

/** A membership request as the router hands it to the org handlers. */
function authed(method: string, callerId: number, orgId: number, memberId: number, body?: unknown) {
    const req = makeRequest(method, `/api/organizations/${orgId}/members/${memberId}`, body) as any;
    req.user = { userId: callerId, email: 'u@example.com', iat: 0, exp: 9999999999 };
    req.params = { orgId: String(orgId), memberUserId: String(memberId) };
    return req;
}

function ownerCount(orgId: number): number {
    return d1.query<{ c: number }>(
        "SELECT COUNT(*) c FROM user_organizations WHERE organization_id = ? AND role = 'super_admin'",
        orgId
    )[0].c;
}

describe('recovery codes are scoped to the account that owns them', () => {
    it('will not redeem another account’s code', async () => {
        const alice = addUser('alice@example.com');
        const mallory = addUser('mallory@example.com');
        giveRecoveryCode(alice, 'AAAA-BBBB-CCCC');

        expect(await consumeRecoveryCode(env, mallory, 'AAAA-BBBB-CCCC')).toBe(false);

        const [row] = d1.query<{ used_at: string | null }>(
            'SELECT used_at FROM user_recovery_codes WHERE user_id = ?', alice
        );
        expect(row.used_at).toBeNull();
    });

    it('redeems the owner’s own code exactly once', async () => {
        const alice = addUser('alice@example.com');
        giveRecoveryCode(alice, 'AAAA-BBBB-CCCC');

        expect(await consumeRecoveryCode(env, alice, 'AAAA-BBBB-CCCC')).toBe(true);
        expect(await consumeRecoveryCode(env, alice, 'AAAA-BBBB-CCCC')).toBe(false);
    });

    it('rejects a code that was never issued', async () => {
        const alice = addUser('alice@example.com');
        giveRecoveryCode(alice, 'AAAA-BBBB-CCCC');

        expect(await consumeRecoveryCode(env, alice, 'ZZZZ-ZZZZ-ZZZZ')).toBe(false);
    });

    it('does not let one account’s redemption consume an identical code held by another', async () => {
        const alice = addUser('alice@example.com');
        const bob = addUser('bob@example.com');
        giveRecoveryCode(alice, 'SAME-CODE-HERE');
        giveRecoveryCode(bob, 'SAME-CODE-HERE');

        expect(await consumeRecoveryCode(env, alice, 'SAME-CODE-HERE')).toBe(true);

        const [bobRow] = d1.query<{ used_at: string | null }>(
            'SELECT used_at FROM user_recovery_codes WHERE user_id = ?', bob
        );
        expect(bobRow.used_at).toBeNull();
        expect(await consumeRecoveryCode(env, bob, 'SAME-CODE-HERE')).toBe(true);
    });
});

describe('an organisation cannot be left without an owner', () => {
    it('refuses to let the sole owner demote themselves', async () => {
        const owner = addUser('owner@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');

        expect((await handleUpdateMemberRole(
            authed('PUT', owner, org, owner, { role: 'member' }), env, mockCtx
        )).status).toBe(403);
        expect(ownerCount(org)).toBe(1);
    });

    it('refuses to let an admin demote the sole owner', async () => {
        const owner = addUser('owner@example.com');
        const admin = addUser('admin@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(admin, org, 'admin');

        expect((await handleUpdateMemberRole(
            authed('PUT', admin, org, owner, { role: 'member' }), env, mockCtx
        )).status).toBe(403);
        expect(ownerCount(org)).toBe(1);
    });

    it('refuses to let an admin remove the sole owner', async () => {
        const owner = addUser('owner@example.com');
        const admin = addUser('admin@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(admin, org, 'admin');

        expect((await handleRemoveMember(
            authed('DELETE', admin, org, owner), env, mockCtx
        )).status).toBe(403);
        expect(ownerCount(org)).toBe(1);
    });

    it('refuses to let the sole owner remove themselves', async () => {
        const owner = addUser('owner@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');

        expect((await handleRemoveMember(
            authed('DELETE', owner, org, owner), env, mockCtx
        )).status).toBe(403);
        expect(ownerCount(org)).toBe(1);
    });

    it('allows demoting an owner while a second owner remains', async () => {
        const a = addUser('a@example.com');
        const b = addUser('b@example.com');
        const org = addOrg('Acme', a);
        addMember(a, org, 'super_admin');
        addMember(b, org, 'super_admin');

        expect((await handleUpdateMemberRole(
            authed('PUT', a, org, b, { role: 'member' }), env, mockCtx
        )).status).toBe(200);
        expect(ownerCount(org)).toBe(1);
    });

    it('lets an owner remove a plain member', async () => {
        const owner = addUser('owner@example.com');
        const member = addUser('member@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(member, org, 'member');

        expect((await handleRemoveMember(
            authed('DELETE', owner, org, member), env, mockCtx
        )).status).toBe(200);
        expect(d1.query<{ c: number }>(
            'SELECT COUNT(*) c FROM user_organizations WHERE organization_id = ?', org
        )[0].c).toBe(1);
    });
});

// Migrated from tests/backend/organizations.test.ts (#89 §6), where each of
// these drove a mock whose `first()` returned a different role on each call —
// first the caller's, then the target's — sequenced by a counter. That is
// order-dependent (any added query silently shifts every later answer) and,
// worse, it can express states SQL cannot: the same row returning two different
// roles. Here the two roles are two real rows, and the endpoint reads whichever
// one it actually asked for.
describe('membership changes, against rows rather than a call counter', () => {
    it('lets an owner change a member’s role, and the change lands in the database', async () => {
        const owner = addUser('owner@example.com');
        const member = addUser('member@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(member, org, 'member');

        const res = await handleUpdateMemberRole(
            authed('PUT', owner, org, member, { role: 'admin' }), env, mockCtx
        );

        expect(res.status).toBe(200);
        // The mocked version asserted only the status code, so it could not
        // tell a successful UPDATE from one bound to the wrong user.
        expect(roleOf(member, org)).toBe('admin');
        expect(roleOf(owner, org)).toBe('super_admin');
    });

    it('refuses a plain member trying to change anyone’s role', async () => {
        const owner = addUser('owner@example.com');
        const member = addUser('member@example.com');
        const other = addUser('other@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(member, org, 'member');
        addMember(other, org, 'member');

        const res = await handleUpdateMemberRole(
            authed('PUT', member, org, other, { role: 'admin' }), env, mockCtx
        );

        expect(res.status).toBe(403);
        expect(roleOf(other, org)).toBe('member');
    });

    it('refuses an admin trying to remove an owner', async () => {
        const owner = addUser('owner@example.com');
        const admin = addUser('admin@example.com');
        const second = addUser('second@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(second, org, 'super_admin');
        addMember(admin, org, 'admin');

        // Two owners exist, so this is refused by rank, not by any last-owner
        // consideration — the distinction the mocked test could not draw.
        const res = await handleRemoveMember(authed('DELETE', admin, org, owner), env, mockCtx);

        expect(res.status).toBe(403);
        expect(roleOf(owner, org)).toBe('super_admin');
    });

    it('revokes the removed member’s vault key shares and names the vaults to rotate', async () => {
        // The most valuable of the migrated tests: deleting the membership is
        // not enough, because vault_key_shares is what actually unwraps the
        // vault key. The mocked version asserted a batch *length* of 3 — which
        // never showed that the right rows were bound, or that anything was
        // deleted at all.
        const owner = addUser('owner@example.com');
        const member = addUser('member@example.com');
        const stayer = addUser('stayer@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(member, org, 'member');
        addMember(stayer, org, 'member');

        const shared = addOrgVault(org, 'Team');
        const other = addOrgVault(org, 'Ops');
        // A vault belonging to a different organisation, to prove the query is
        // scoped: the member holds a share on it and must keep it.
        const elsewhere = addOrg('Globex', owner);
        const unrelated = addOrgVault(elsewhere, 'Elsewhere');

        for (const vault of [shared, other, unrelated]) {
            for (const user of [member, stayer]) giveKeyShare(vault, user);
        }

        const res = await handleRemoveMember(authed('DELETE', owner, org, member), env, mockCtx);
        expect(res.status).toBe(200);

        const body = await res.json() as { rotateVaultIds: number[] };
        expect(body.rotateVaultIds.sort()).toEqual([shared, other].sort());

        // The membership is gone...
        expect(roleOf(member, org)).toBeNull();
        // ...along with the shares that would still have opened those vaults...
        expect(shareHolders(shared)).toEqual([stayer]);
        expect(shareHolders(other)).toEqual([stayer]);
        // ...and nothing else was touched.
        expect(shareHolders(unrelated).sort()).toEqual([member, stayer].sort());
        expect(roleOf(stayer, org)).toBe('member');
    });
});

// The invariant the tests above protect — "an organisation always has at least
// one owner" — is enforced on the membership endpoints and nowhere else.
// Account deletion reaches the same state by a different road: users has
// ON DELETE CASCADE onto user_organizations (migrations/0002_super_admin_role.sql),
// so deleting the sole owner's account silently takes the membership row with
// it (#74).
//
// Written as a failing test rather than a comment, per #83 §D: a known
// violation belongs in the suite as a tracked, executable TODO, not in prose
// that nothing checks. `it.fails` passes while the bug exists and — this is the
// point — starts FAILING the moment someone fixes #74, which is what tells them
// to promote it to a normal `it`.
//
// This documents the database's behaviour directly. Routing it through
// handleDeleteAccount would drag in scrypt, the rate limiter and R2; the
// cascade is the mechanism, and it is what a fix has to interrupt.
describe('#74 — account deletion bypasses the last-owner invariant', () => {
    it.fails('keeps an owner on the organisation when the sole owner deletes their account', () => {
        const owner = addUser('owner@example.com');
        const member = addUser('member@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(member, org, 'member');

        expect(ownerCount(org)).toBe(1);

        // Exactly what handleDeleteAccount issues (src/auth.ts).
        d1.db.prepare('DELETE FROM users WHERE id = ?').run(owner);

        expect(ownerCount(org)).toBeGreaterThan(0);
    });

    // What the cascade actually does, which is worse than #74 describes and in a
    // different way. #74 says the organisation is "left with members but zero
    // owners" and "permanently stranded". It is not: organizations.created_by
    // is itself ON DELETE CASCADE (migrations/0001_init.sql:33), so the whole
    // organisation row is deleted, and that cascades again through
    // user_organizations.organization_id — removing *every other member's*
    // membership too.
    //
    // Vaults do not follow, because vaults.owner_id is a TEXT tag ('org_7')
    // with no foreign key. So the shared vault rows and their R2 blobs outlive
    // the organisation that granted access to them, pointing at an id nothing
    // resolves.
    //
    // Net effect: one user deleting their own account silently destroys every
    // other member's access to the shared vaults, and leaves the ciphertext
    // behind, billable and unreachable. That is data loss for third parties
    // triggered by a routine self-service action.
    //
    // Asserted as current behaviour, not endorsed: it is the thing a fix has to
    // change, and pinning it means the fix cannot land silently.
    it('currently deletes the whole organisation and every membership, orphaning its vaults', () => {
        const owner = addUser('owner@example.com');
        const member = addUser('member@example.com');
        const org = addOrg('Acme', owner);
        addMember(owner, org, 'super_admin');
        addMember(member, org, 'member');

        d1.db.prepare(
            `INSERT INTO vaults (name, owner_id, owner_type, r2_object_key)
             VALUES ('Team secrets', ?, 'organization', 'vaults/team-secrets')`
        ).run(`org_${org}`);

        d1.db.prepare('DELETE FROM users WHERE id = ?').run(owner);

        const count = (sql: string, ...args: unknown[]) =>
            d1.query<{ c: number }>(sql, ...args)[0].c;

        // The organisation is gone, not merely unowned.
        expect(count('SELECT COUNT(*) c FROM organizations WHERE id = ?', org)).toBe(0);
        // And so is the surviving member's membership — nobody was removed by
        // any endpoint, and no audit row records it.
        expect(count('SELECT COUNT(*) c FROM user_organizations WHERE organization_id = ?', org)).toBe(0);
        expect(count('SELECT COUNT(*) c FROM users WHERE id = ?', member)).toBe(1);

        // The vault survives, pointing at an organisation that no longer exists.
        expect(count("SELECT COUNT(*) c FROM vaults WHERE owner_id = ?", `org_${org}`)).toBe(1);
    });
});
