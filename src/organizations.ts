// src/organizations.ts

import { CustomRequest, Env, Organization, UserOrganization, User, ADMIN_ROLES } from './types.js';
import { logAudit } from './auditLog.js';
import {
    jsonResponse,
    parseId,
    normalizeEmail,
    safeJson,
    auditErrorCode,
    isSaneText,
    MAX_NAME_LENGTH,
    MAX_DESCRIPTION_LENGTH
} from './utils.js';

export async function handleCreateOrganization(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const body = await safeJson<{ name?: string; description?: string }>(request);
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!body) {
        return jsonResponse({ message: "Invalid JSON body." }, 400);
    }
    const { name, description } = body;

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'ORG_CREATE_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!name) {
        logAudit(env, ctx, user.userId, 'ORG_CREATE_FAILURE', { reason: 'Missing name' }, ipAddress, userAgent);
        return jsonResponse({ message: "Organization name is required." }, 400);
    }
    if (!isSaneText(name, MAX_NAME_LENGTH) || !isSaneText(description, MAX_DESCRIPTION_LENGTH)) {
        logAudit(env, ctx, user.userId, 'ORG_CREATE_FAILURE', { reason: 'Field too long' }, ipAddress, userAgent);
        return jsonResponse({
            message: `Organization name must be at most ${MAX_NAME_LENGTH} characters and the description at most ${MAX_DESCRIPTION_LENGTH}.`
        }, 400);
    }

    try {
        const orgInsertResult = await env.DB.prepare(
            `INSERT INTO organizations (name, description, created_by) VALUES (?, ?, ?)`
        )
            .bind(name, description || null, user.userId)
            .run();

        if (!orgInsertResult.success) {
            throw new Error("Failed to insert organization.");
        }

        const organizationId = orgInsertResult.meta?.last_row_id;
        if (!organizationId) {
            throw new Error("Could not retrieve new organization ID.");
        }

        // Creator becomes super_admin
        const memberResult = await env.DB.prepare(
            `INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, 'super_admin')`
        )
            .bind(user.userId, organizationId)
            .run();

        if (!memberResult.success) {
            await env.DB.prepare("DELETE FROM organizations WHERE id = ?").bind(organizationId).run();
            throw new Error("Failed to add creator as organization owner.");
        }

        logAudit(env, ctx, user.userId, 'ORG_CREATE_SUCCESS', { orgId: organizationId, name }, ipAddress, userAgent);
        return jsonResponse({ id: organizationId, name, description: description || null, created_by: user.userId, role: 'super_admin' }, 201);
    } catch (error: any) {
        console.error("Create organization error:", error);
        logAudit(env, ctx, user.userId, 'ORG_CREATE_FAILURE', { name, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while creating organization." }, 500);
    }
}

export async function handleGetOrganizations(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'ORG_LIST_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }

    try {
        const organizations: Organization[] = await env.DB.prepare(
            `SELECT o.id, o.name, o.description, uo.role
             FROM organizations o
             JOIN user_organizations uo ON o.id = uo.organization_id
             WHERE uo.user_id = ?`
        ).bind(user.userId).all().then(res => res.results as unknown as Organization[]);

        // No ORG_LIST_SUCCESS row: prefetched on every app boot alongside the
        // vault list, so it recorded page loads rather than actions (#73).
        return jsonResponse(organizations);
    } catch (error: any) {
        console.error("Get organizations error:", error);
        logAudit(env, ctx, user.userId, 'ORG_LIST_FAILURE', { error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while fetching organizations." }, 500);
    }
}

export async function handleGetOrgMembers(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const orgIdParam = request.params?.orgId;
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user?.userId) return jsonResponse({ message: "Unauthorized." }, 401);

    const orgId = parseId(orgIdParam);
    if (orgId === null) return jsonResponse({ message: "Bad Request: Invalid organization ID." }, 400);

    try {
        const callerMembership: { role: string } | null = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(user.userId, orgId).first();

        if (!callerMembership) {
            logAudit(env, ctx, user.userId, 'ORG_GET_MEMBERS_FAILURE', { orgId, reason: 'Not a member' }, ipAddress, userAgent);
            return jsonResponse({ message: "Forbidden: You are not a member of this organization." }, 403);
        }

        const members = await env.DB.prepare(
            `SELECT u.id AS userId, u.email, uo.role
             FROM user_organizations uo
             JOIN users u ON uo.user_id = u.id
             WHERE uo.organization_id = ?
             ORDER BY uo.joined_at ASC`
        ).bind(orgId).all().then(res => res.results as unknown as { userId: number; email: string; role: string }[]);

        // Read-only listing, fired on every visit to the members view (#73).
        return jsonResponse(members);
    } catch (error: any) {
        console.error("Get org members error:", error);
        logAudit(env, ctx, user.userId, 'ORG_GET_MEMBERS_FAILURE', { orgId, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while fetching members." }, 500);
    }
}

export async function handleUpdateMemberRole(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const orgIdParam = request.params?.orgId;
    const memberUserIdParam = request.params?.memberUserId;
    const body = await safeJson<{ role?: string }>(request);
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!body) return jsonResponse({ message: "Invalid JSON body." }, 400);
    const { role } = body;

    if (!user?.userId) return jsonResponse({ message: "Unauthorized." }, 401);

    const orgId = parseId(orgIdParam);
    const targetUserId = parseId(memberUserIdParam);
    if (orgId === null || targetUserId === null)
        return jsonResponse({ message: "Bad Request: Invalid ID format." }, 400);

    if (typeof role !== 'string' || !['member', 'admin', 'super_admin'].includes(role))
        return jsonResponse({ message: "Invalid role. Must be member, admin, or super_admin." }, 400);

    if (user.userId === targetUserId)
        return jsonResponse({ message: "Forbidden: Cannot change your own role." }, 403);

    try {
        const callerRole: { role: string } | null = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(user.userId, orgId).first();

        if (!callerRole || callerRole.role !== 'super_admin') {
            logAudit(env, ctx, user.userId, 'ORG_UPDATE_ROLE_FAILURE', { orgId, reason: 'Not super_admin' }, ipAddress, userAgent);
            return jsonResponse({ message: "Forbidden: Only owners can change member roles." }, 403);
        }

        // Guard: cannot demote the last super_admin
        const targetCurrentRole: { role: string } | null = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(targetUserId, orgId).first();

        if (!targetCurrentRole)
            return jsonResponse({ message: "Member not found in this organization." }, 404);

        if (targetCurrentRole.role === 'super_admin' && role !== 'super_admin') {
            const superAdminCount: { count: number } | null = await env.DB.prepare(
                `SELECT COUNT(*) as count FROM user_organizations WHERE organization_id = ? AND role = 'super_admin'`
            ).bind(orgId).first();

            if ((superAdminCount?.count ?? 0) <= 1) {
                return jsonResponse({ message: "Forbidden: Cannot demote the last owner." }, 409);
            }
        }

        await env.DB.prepare(
            `UPDATE user_organizations SET role = ? WHERE user_id = ? AND organization_id = ?`
        ).bind(role, targetUserId, orgId).run();

        logAudit(env, ctx, user.userId, 'ORG_UPDATE_ROLE_SUCCESS', { orgId, targetUserId, role }, ipAddress, userAgent);
        return jsonResponse({ message: `Role updated to ${role}.` });
    } catch (error: any) {
        console.error("Update member role error:", error);
        logAudit(env, ctx, user.userId, 'ORG_UPDATE_ROLE_FAILURE', { orgId, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while updating role." }, 500);
    }
}

export async function handleRemoveMember(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const orgIdParam = request.params?.orgId;
    const memberUserIdParam = request.params?.memberUserId;
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user?.userId) return jsonResponse({ message: "Unauthorized." }, 401);

    const orgId = parseId(orgIdParam);
    const targetUserId = parseId(memberUserIdParam);
    if (orgId === null || targetUserId === null)
        return jsonResponse({ message: "Bad Request: Invalid ID format." }, 400);

    if (user.userId === targetUserId)
        return jsonResponse({ message: "Forbidden: Cannot remove yourself from the organization." }, 403);

    try {
        const callerRole: { role: string } | null = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(user.userId, orgId).first();

        if (!callerRole || !ADMIN_ROLES.includes(callerRole.role as any)) {
            logAudit(env, ctx, user.userId, 'ORG_REMOVE_MEMBER_FAILURE', { orgId, reason: 'Not admin' }, ipAddress, userAgent);
            return jsonResponse({ message: "Forbidden: Only admins can remove members." }, 403);
        }

        const targetRole: { role: string } | null = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(targetUserId, orgId).first();

        if (!targetRole)
            return jsonResponse({ message: "Member not found in this organization." }, 404);

        // Only super_admin can remove another super_admin
        if (targetRole.role === 'super_admin' && callerRole.role !== 'super_admin') {
            return jsonResponse({ message: "Forbidden: Only owners can remove other owners." }, 403);
        }

        // Guard: cannot remove the last super_admin
        if (targetRole.role === 'super_admin') {
            const superAdminCount: { count: number } | null = await env.DB.prepare(
                `SELECT COUNT(*) as count FROM user_organizations WHERE organization_id = ? AND role = 'super_admin'`
            ).bind(orgId).first();

            if ((superAdminCount?.count ?? 0) <= 1) {
                return jsonResponse({ message: "Forbidden: Cannot remove the last owner." }, 409);
            }
        }

        // Vaults the removed member could open via this organisation. Their key
        // shares must go with the membership, or the row keeps unwrapping the
        // vault key long after access was revoked.
        const affectedVaults = await env.DB.prepare(
            `SELECT v.id FROM vaults v
             JOIN vault_access_controls vac ON v.id = vac.vault_id
             WHERE vac.entity_id = 'org_' || ? AND vac.entity_type = 'organization'`
        ).bind(orgId).all().then(r => r.results as unknown as { id: number }[]);

        const statements = [
            env.DB.prepare(`DELETE FROM user_organizations WHERE user_id = ? AND organization_id = ?`)
                .bind(targetUserId, orgId)
        ];
        const dropShare = env.DB.prepare("DELETE FROM vault_key_shares WHERE vault_id = ? AND user_id = ?");
        for (const vault of affectedVaults) {
            statements.push(dropShare.bind(vault.id, targetUserId));
        }
        await env.DB.batch(statements);

        logAudit(env, ctx, user.userId, 'ORG_REMOVE_MEMBER_SUCCESS',
            { orgId, targetUserId, sharesRevoked: affectedVaults.length }, ipAddress, userAgent);
        // Deleting the share is necessary but not sufficient: the removed member
        // may have cached the vault key while they had access. The client is told
        // which vaults now need their key rotated and re-wrapped for the members
        // who remain.
        return jsonResponse({
            message: "Member removed.",
            rotateVaultIds: affectedVaults.map(v => v.id)
        });
    } catch (error: any) {
        console.error("Remove member error:", error);
        logAudit(env, ctx, user.userId, 'ORG_REMOVE_MEMBER_FAILURE', { orgId, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while removing member." }, 500);
    }
}

export async function handleDeleteOrganization(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const orgIdParam = request.params?.orgId;
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user?.userId) return jsonResponse({ message: "Unauthorized." }, 401);

    const orgId = parseId(orgIdParam);
    if (orgId === null) return jsonResponse({ message: "Bad Request: Invalid organization ID." }, 400);

    try {
        const callerRole: { role: string } | null = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(user.userId, orgId).first();

        if (!callerRole || callerRole.role !== 'super_admin') {
            logAudit(env, ctx, user.userId, 'ORG_DELETE_FAILURE', { orgId, reason: 'Not super_admin' }, ipAddress, userAgent);
            return jsonResponse({ message: "Forbidden: Only owners can delete organizations." }, 403);
        }

        // Collect org vault R2 keys before deletion
        const orgVaults = await env.DB.prepare(
            `SELECT r2_object_key FROM vaults WHERE owner_id = ? AND owner_type = 'organization'`
        ).bind(`org_${orgId}`).all().then(r => r.results as unknown as { r2_object_key: string }[]);

        // Atomically delete all DB records
        await env.DB.batch([
            env.DB.prepare(
                `DELETE FROM vault_access_controls WHERE vault_id IN
                 (SELECT id FROM vaults WHERE owner_id = ? AND owner_type = 'organization')`
            ).bind(`org_${orgId}`),
            env.DB.prepare(
                `DELETE FROM vaults WHERE owner_id = ? AND owner_type = 'organization'`
            ).bind(`org_${orgId}`),
            env.DB.prepare(
                `DELETE FROM user_organizations WHERE organization_id = ?`
            ).bind(orgId),
            env.DB.prepare(
                `DELETE FROM organizations WHERE id = ?`
            ).bind(orgId)
        ]);

        // Delete R2 objects after DB records are removed (best-effort)
        for (const vault of orgVaults) {
            await env.VAULTS.delete(vault.r2_object_key);
        }

        logAudit(env, ctx, user.userId, 'ORG_DELETE_SUCCESS', { orgId, vaultsDeleted: orgVaults.length }, ipAddress, userAgent);
        return new Response(null, { status: 204 });
    } catch (error: any) {
        console.error("Delete organization error:", error);
        logAudit(env, ctx, user.userId, 'ORG_DELETE_FAILURE', { orgId, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while deleting organization." }, 500);
    }
}

/**
 * GET /api/organizations/:orgId/member-keys
 *
 * Every member's public key, so an admin who holds a vault key can wrap it for
 * all of them in one pass. Restricted to members of the organisation.
 *
 * `publicKey: null` means that member has not yet completed the auth_version 2
 * upgrade, so nothing can be wrapped for them yet — the caller should say so
 * rather than silently skipping them.
 */
export async function handleGetOrgMemberKeys(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const user = request.user!;
    const orgId = parseId(request.params?.orgId);
    if (orgId === null) return jsonResponse({ message: "Bad Request: Invalid organization ID format." }, 400);

    try {
        const membership = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(user.userId, orgId).first<{ role: string }>();

        if (!membership) {
            return jsonResponse({ message: "Forbidden: You are not a member of this organization." }, 403);
        }

        const members = await env.DB.prepare(
            `SELECT u.id AS userId, u.email, uo.role, uk.public_key AS publicKey
             FROM user_organizations uo
             JOIN users u ON u.id = uo.user_id
             LEFT JOIN user_keys uk ON uk.user_id = u.id
             WHERE uo.organization_id = ?`
        ).bind(orgId).all().then(r => r.results);

        return jsonResponse({ members });
    } catch (error: any) {
        console.error("Get org member keys error:", error);
        return jsonResponse({ message: "Internal Server Error while fetching member keys." }, 500);
    }
}

/**
 * GET /api/organizations/:orgId/key-gaps
 *
 * Members who are entitled to an organisation vault but hold no wrapped copy of
 * its key.
 *
 * Membership and key access are separate facts, and only a client that can
 * already open a vault can close the gap — the server has never seen the key.
 * Until now the wrap happened exactly once, at the moment a member was added, so
 * anything that missed that instant never healed: a member invited before their
 * first sign-in (no keypair to wrap to yet), a vault the inviting admin could not
 * open, a dropped request. They stayed permanently locked out of vaults they were
 * entitled to, told to "ask an administrator" with no action that would help.
 *
 * This endpoint is the missing half — it lets any key-holding member reconcile.
 * It reports only entitlement metadata (who is in the org, who holds a share);
 * no key material, wrapped or otherwise. Restricted to members, not admins, so
 * convergence does not depend on one specific person signing in.
 */
export async function handleGetOrgKeyGaps(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const user = request.user!;
    const orgId = parseId(request.params?.orgId);
    if (orgId === null) return jsonResponse({ message: "Bad Request: Invalid organization ID format." }, 400);

    try {
        const membership = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(user.userId, orgId).first<{ role: string }>();

        if (!membership) {
            return jsonResponse({ message: "Forbidden: You are not a member of this organization." }, 403);
        }

        // One row per (org vault, member) pair that has no share. The
        // `vks.vault_id IS NULL` anti-join is what makes it a gap.
        const rows = await env.DB.prepare(
            `SELECT v.id AS vaultId, v.name AS vaultName,
                    u.id AS userId, u.email AS email, uk.public_key AS publicKey
             FROM vaults v
             JOIN vault_access_controls vac ON vac.vault_id = v.id
                  AND vac.entity_type = 'organization' AND vac.entity_id = 'org_' || ?
             JOIN user_organizations uo ON uo.organization_id = ?
             JOIN users u ON u.id = uo.user_id
             LEFT JOIN user_keys uk ON uk.user_id = u.id
             LEFT JOIN vault_key_shares vks ON vks.vault_id = v.id AND vks.user_id = u.id
             WHERE v.owner_type = 'organization' AND vks.vault_id IS NULL
             ORDER BY v.id`
        ).bind(orgId, orgId).all().then(r => r.results as unknown as {
            vaultId: number; vaultName: string; userId: number; email: string; publicKey: string | null;
        }[]);

        const byVault = new Map<number, {
            vaultId: number; vaultName: string;
            missing: Array<{ userId: number; email: string; publicKey: string }>;
            notUpgraded: Array<{ userId: number; email: string }>;
        }>();

        for (const row of rows) {
            if (!byVault.has(row.vaultId)) {
                byVault.set(row.vaultId, { vaultId: row.vaultId, vaultName: row.vaultName, missing: [], notUpgraded: [] });
            }
            const gap = byVault.get(row.vaultId)!;
            // No public key means they have never signed in since the key
            // hierarchy shipped, so there is nothing to wrap to yet. Reported
            // separately — it needs the member to act, not an admin.
            if (row.publicKey) gap.missing.push({ userId: row.userId, email: row.email, publicKey: row.publicKey });
            else gap.notUpgraded.push({ userId: row.userId, email: row.email });
        }

        return jsonResponse({ gaps: Array.from(byVault.values()) });
    } catch (error: any) {
        console.error("Get org key gaps error:", error);
        return jsonResponse({ message: "Internal Server Error while checking vault key access." }, 500);
    }
}

export async function handleAddMemberToOrganization(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const body = await safeJson<{ memberEmail?: string; role?: 'member' | 'admin' }>(request);
    const orgIdParam = request.params?.orgId;
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!body) {
        return jsonResponse({ message: "Invalid JSON body." }, 400);
    }
    const memberEmail = normalizeEmail(body.memberEmail);
    const { role } = body;

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'ORG_ADD_MEMBER_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!orgIdParam || !memberEmail || typeof role !== 'string' || !['member', 'admin'].includes(role)) {
        logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { reason: 'Missing/invalid fields', orgId: orgIdParam, memberEmail, role }, ipAddress, userAgent);
        return jsonResponse({ message: "Organization ID, member email, and a valid role (member or admin) are required." }, 400);
    }

    const organizationId = parseId(orgIdParam);
    if (organizationId === null) {
        logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: orgIdParam, reason: 'Invalid orgId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid organization ID format." }, 400);
    }

    try {
        const currentUserRole: UserOrganization | null = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(user.userId, organizationId).first();

        if (!currentUserRole || !ADMIN_ROLES.includes(currentUserRole.role as any)) {
            logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: organizationId, reason: 'Permission denied - not admin' }, ipAddress, userAgent);
            return jsonResponse({ message: "Forbidden: You must be an organization admin to add members." }, 403);
        }

        const memberUser: User | null = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(memberEmail).first();
        if (!memberUser) {
            logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: organizationId, memberEmail, reason: 'Member user not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "User with this email not found." }, 404);
        }

        const existingMembership: UserOrganization | null = await env.DB.prepare(
            `SELECT * FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(memberUser.id, organizationId).first();

        if (existingMembership) {
            logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: organizationId, memberEmail, reason: 'Member already exists' }, ipAddress, userAgent);
            return jsonResponse({ message: "User is already a member of this organization." }, 409);
        }

        await env.DB.prepare(
            `INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, ?)`
        )
            .bind(memberUser.id, organizationId, role)
            .run();

        logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_SUCCESS', { orgId: organizationId, memberEmail, role }, ipAddress, userAgent);
        return jsonResponse({ message: `Member ${memberEmail} added to organization ${organizationId} with role ${role}.` }, 200);
    } catch (error: any) {
        console.error("Add member to organization error:", error);
        logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: organizationId, memberEmail, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while adding member." }, 500);
    }
}
