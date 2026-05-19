// src/organizations.ts

import { CustomRequest, Env, Organization, UserOrganization, User } from './types.js';
import { logAudit } from './auditLog.js';
import { jsonResponse } from './utils.js';

export async function handleCreateOrganization(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { name, description } = await request.json() as { name: string; description?: string };
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'ORG_CREATE_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!name) {
        logAudit(env, ctx, user.userId, 'ORG_CREATE_FAILURE', { reason: 'Missing name' }, ipAddress, userAgent);
        return jsonResponse({ message: "Organization name is required." }, 400);
    }

    try {
        // Start a transaction for creating org and adding creator as admin
        await env.DB.exec('BEGIN;');
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

        await env.DB.prepare(
            `INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, 'admin')`
        )
            .bind(user.userId, organizationId)
            .run();

        await env.DB.exec('COMMIT;');

        logAudit(env, ctx, user.userId, 'ORG_CREATE_SUCCESS', { orgId: organizationId, name }, ipAddress, userAgent);
        return jsonResponse({ id: organizationId, name, description: description || null, created_by: user.userId }, 201);
    } catch (error: any) {
        await env.DB.exec('ROLLBACK;');
        console.error("Create organization error:", error);
        logAudit(env, ctx, user.userId, 'ORG_CREATE_FAILURE', { name, error: error.message }, ipAddress, userAgent);
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

        logAudit(env, ctx, user.userId, 'ORG_LIST_SUCCESS', { count: organizations.length }, ipAddress, userAgent);
        return jsonResponse(organizations);
    } catch (error: any) {
        console.error("Get organizations error:", error);
        logAudit(env, ctx, user.userId, 'ORG_LIST_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while fetching organizations." }, 500);
    }
}

export async function handleAddMemberToOrganization(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { memberEmail, role } = await request.json() as { memberEmail: string; role: 'member' | 'admin' };
    const orgIdParam = request.params?.orgId;
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'ORG_ADD_MEMBER_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!orgIdParam || !memberEmail || !['member', 'admin'].includes(role)) {
        logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { reason: 'Missing/invalid fields', orgId: orgIdParam, memberEmail, role }, ipAddress, userAgent);
        return jsonResponse({ message: "Organization ID, member email, and a valid role are required." }, 400);
    }

    const organizationId = parseInt(orgIdParam);
    if (isNaN(organizationId)) {
        logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: orgIdParam, reason: 'Invalid orgId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid organization ID format." }, 400);
    }

    try {
        // 1. Check if the current user is an admin of this organization
        const currentUserRole: UserOrganization | null = await env.DB.prepare(
            `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(user.userId, organizationId).first();

        if (!currentUserRole || currentUserRole.role !== 'admin') {
            logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: organizationId, reason: 'Permission denied - not admin' }, ipAddress, userAgent);
            return jsonResponse({ message: "Forbidden: You must be an organization admin to add members." }, 403);
        }

        // 2. Find the user to be added
        const memberUser: User | null = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(memberEmail).first();
        if (!memberUser) {
            logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: organizationId, memberEmail, reason: 'Member user not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "User with this email not found." }, 404);
        }

        // 3. Check if member is already in the organization
        const existingMembership: UserOrganization | null = await env.DB.prepare(
            `SELECT * FROM user_organizations WHERE user_id = ? AND organization_id = ?`
        ).bind(memberUser.id, organizationId).first();

        if (existingMembership) {
            logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: organizationId, memberEmail, reason: 'Member already exists' }, ipAddress, userAgent);
            return jsonResponse({ message: "User is already a member of this organization." }, 409);
        }

        // 4. Add the member
        await env.DB.prepare(
            `INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, ?)`
        )
            .bind(memberUser.id, organizationId, role)
            .run();

        logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_SUCCESS', { orgId: organizationId, memberEmail, role }, ipAddress, userAgent);
        return jsonResponse({ message: `Member ${memberEmail} added to organization ${organizationId} with role ${role}.` }, 200);
    } catch (error: any) {
        console.error("Add member to organization error:", error);
        logAudit(env, ctx, user.userId, 'ORG_ADD_MEMBER_FAILURE', { orgId: organizationId, memberEmail, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while adding member." }, 500);
    }
}
