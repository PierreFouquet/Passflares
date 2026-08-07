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
    function authed(method: string, callerId: number, orgId: number, memberId: number, body?: unknown) {
        const req = makeRequest(method, `/api/organizations/${orgId}/members/${memberId}`, body) as any;
        req.user = { userId: callerId, email: 'u@example.com', iat: 0, exp: 9999999999 };
        req.params = { orgId: String(orgId), memberUserId: String(memberId) };
        return req;
    }

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
