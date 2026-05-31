// src/vaults.ts

import { CustomRequest, Env, VaultMetadata, EncryptedVaultBlob, OrgRole, ADMIN_ROLES } from './types.js'; // Ensure correct path and .js extension
import { logAudit } from './auditLog.js'; // Ensure correct path and .js extension
import { jsonResponse } from './utils.js'; // Ensure correct path and .js extension

export async function handleCreateVault(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { name, description, ownerId, ownerType, initialPermissionLevel } = await request.json() as {
        name: string;
        description?: string;
        ownerId: string; // 'user_X' or 'org_Y'
        ownerType: 'user' | 'organization';
        initialPermissionLevel: 'read' | 'write' | 'manage';
    };
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'VAULT_CREATE_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!name || !ownerId || !ownerType || !initialPermissionLevel) {
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Vault name, owner ID, owner type, and initial permission are required." }, 400);
    }
    if (!['user', 'organization'].includes(ownerType)) {
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Invalid owner type', ownerType }, ipAddress, userAgent);
        return jsonResponse({ message: "Invalid owner type." }, 400);
    }
    if (!['read', 'write', 'manage'].includes(initialPermissionLevel)) {
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Invalid permission level', initialPermissionLevel }, ipAddress, userAgent);
        return jsonResponse({ message: "Invalid initial permission level." }, 400);
    }

    try {
        // Validate ownerId based on ownerType
        if (ownerType === 'user' && ownerId !== `user_${user.userId}`) {
            logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Unauthorized user owner ID' }, ipAddress, userAgent);
            return jsonResponse({ message: "Unauthorized: Cannot create vault for another user." }, 403);
        } else if (ownerType === 'organization') {
            const orgId = parseInt(ownerId.split('_')[1]);
            if (isNaN(orgId)) {
                logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Invalid orgId format' }, ipAddress, userAgent);
                return jsonResponse({ message: "Invalid organization ID format." }, 400);
            }
            // Check if user is an admin of this organization. Accept any
            // administrative role — the org creator is seeded as 'super_admin',
            // so gating on 'admin' alone returned 403 to owners creating a vault
            // for their own org, which the client surfaced as a forced logout.
            const orgMember: { role: string } | null = await env.DB.prepare(
                `SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?`
            ).bind(user.userId, orgId).first();

            if (!orgMember || !ADMIN_ROLES.includes(orgMember.role as OrgRole)) {
                logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Not organization admin', orgId }, ipAddress, userAgent);
                return jsonResponse({ message: "You must be an admin of the organization to create a vault for it." }, 403);
            }
        }

        const r2ObjectKey = `${ownerId}_${crypto.randomUUID()}`;
        const currentKeyVersion = 'v1';

        const vaultInsertResult = await env.DB.prepare(
            `INSERT INTO vaults (name, description, owner_id, owner_type, r2_object_key, current_key_version)
             VALUES (?, ?, ?, ?, ?, ?)`
        )
            .bind(name, description || null, ownerId, ownerType, r2ObjectKey, currentKeyVersion)
            .run();

        if (!vaultInsertResult.success || !vaultInsertResult.meta?.last_row_id) {
            throw new Error("Failed to insert vault metadata.");
        }

        const vaultId = vaultInsertResult.meta.last_row_id;

        // Record initial access control; if this fails, compensate by removing the vault
        const aclResult = await env.DB.prepare(
            `INSERT INTO vault_access_controls (vault_id, entity_id, entity_type, permission_level)
             VALUES (?, ?, ?, ?)`
        )
            .bind(vaultId, ownerId, ownerType, initialPermissionLevel)
            .run();

        if (!aclResult.success) {
            await env.DB.prepare("DELETE FROM vaults WHERE id = ?").bind(vaultId).run();
            throw new Error("Failed to insert vault access control.");
        }

        logAudit(env, ctx, user.userId, 'VAULT_CREATE_SUCCESS', { vaultId, name, ownerId, ownerType }, ipAddress, userAgent);
        return jsonResponse({
            id: vaultId,
            name,
            description: description || null,
            owner_id: ownerId,
            owner_type: ownerType,
            r2_object_key: r2ObjectKey,
            current_key_version: currentKeyVersion
        }, 201);
    } catch (error: any) {
        console.error("Create vault error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { name, ownerId, ownerType, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while creating vault." }, 500);
    }
}

export async function handleGetVaults(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'VAULT_LIST_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }

    try {
        // Get vaults owned directly by the user or where the user has explicit access
        const vaults: VaultMetadata[] = await env.DB.prepare(
            `SELECT v.id, v.name, v.description, v.owner_id, v.owner_type, v.r2_object_key, v.current_key_version,
                    CASE
                        WHEN v.owner_id = ? AND v.owner_type = 'user' THEN 'manage'
                        ELSE vac.permission_level
                    END AS permission_level
             FROM vaults v
             LEFT JOIN vault_access_controls vac ON v.id = vac.vault_id
             WHERE (v.owner_id = ? AND v.owner_type = 'user') OR (vac.entity_id = ? AND vac.entity_type = 'user')`
        )
            .bind(`user_${user.userId}`, `user_${user.userId}`, `user_${user.userId}`)
            .all()
            .then(res => res.results as unknown as VaultMetadata[]);

        // Get vaults accessible via organizations the user is a member of
        const orgVaults: VaultMetadata[] = await env.DB.prepare(
            `SELECT v.id, v.name, v.description, v.owner_id, v.owner_type, v.r2_object_key, v.current_key_version,
                    vac.permission_level
             FROM vaults v
             JOIN vault_access_controls vac ON v.id = vac.vault_id
             JOIN user_organizations uo ON vac.entity_id = 'org_' || uo.organization_id AND vac.entity_type = 'organization'
             WHERE uo.user_id = ?`
        )
            .bind(user.userId)
            .all()
            .then(res => res.results as unknown as VaultMetadata[]);

        // Combine and deduplicate vaults (a vault might be accessible directly and via an org)
        const allVaultsMap = new Map<number, VaultMetadata>();
        [...vaults, ...orgVaults].forEach(vault => {
            if (!allVaultsMap.has(vault.id) || (allVaultsMap.has(vault.id) &&
                (vault.permission_level === 'manage' ||
                 (vault.permission_level === 'write' && allVaultsMap.get(vault.id)?.permission_level === 'read')))) {
                // Prioritize higher permissions
                allVaultsMap.set(vault.id, vault);
            }
        });

        const distinctVaults = Array.from(allVaultsMap.values());

        logAudit(env, ctx, user.userId, 'VAULT_LIST_SUCCESS', { count: distinctVaults.length }, ipAddress, userAgent);
        return jsonResponse(distinctVaults);
    } catch (error: any) {
        console.error("Get vaults error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_LIST_FAILURE', { error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while fetching vaults." }, 500);
    }
}

export async function handleUploadVault(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const vaultIdParam = request.params?.vaultId;
    const { encryptedData } = await request.json() as { encryptedData: EncryptedVaultBlob };
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'VAULT_UPLOAD_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!vaultIdParam || !encryptedData || !encryptedData.iv || !encryptedData.ciphertext) {
        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { reason: 'Missing fields', vaultId: vaultIdParam }, ipAddress, userAgent);
        return jsonResponse({ message: "Vault ID and encrypted data (IV, ciphertext) are required." }, 400);
    }

    const vaultId = parseInt(vaultIdParam);
    if (isNaN(vaultId)) {
        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { vaultId: vaultIdParam, reason: 'Invalid vaultId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);
    }

    try {
        const vault: VaultMetadata | null = await env.DB.prepare("SELECT r2_object_key FROM vaults WHERE id = ?").bind(vaultId).first();
        if (!vault) {
            logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { vaultId, reason: 'Vault not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Vault not found." }, 404);
        }

        // R2 objects are stored as ArrayBuffer, so convert hex string to Uint8Array
        const dataToStore = JSON.stringify(encryptedData);
        await env.VAULTS.put(vault.r2_object_key, dataToStore);

        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_SUCCESS', { vaultId }, ipAddress, userAgent);
        return new Response(null, { status: 204 }); // No Content
    } catch (error: any) {
        console.error("Upload vault error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { vaultId, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while uploading vault data." }, 500);
    }
}

export async function handleDownloadVault(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const vaultIdParam = request.params?.vaultId;
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'VAULT_DOWNLOAD_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!vaultIdParam) {
        logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_FAILURE', { reason: 'Missing vaultId' }, ipAddress, userAgent);
        return jsonResponse({ message: "Vault ID is required." }, 400);
    }

    const vaultId = parseInt(vaultIdParam);
    if (isNaN(vaultId)) {
        logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_FAILURE', { vaultId: vaultIdParam, reason: 'Invalid vaultId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);
    }

    try {
        const vault: VaultMetadata | null = await env.DB.prepare("SELECT r2_object_key FROM vaults WHERE id = ?").bind(vaultId).first();
        if (!vault) {
            logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_FAILURE', { vaultId, reason: 'Vault not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Vault not found." }, 404);
        }

        const object = await env.VAULTS.get(vault.r2_object_key);
        if (object === null) {
            // If the R2 object doesn't exist, it means the vault is new/empty
            logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_SUCCESS', { vaultId, status: 'empty' }, ipAddress, userAgent);
            return new Response(null, { status: 204 }); // 204 No Content for empty vault
        }

        // R2 object content is usually a ReadableStream or ArrayBuffer
        const encryptedData: EncryptedVaultBlob = await object.json();

        logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_SUCCESS', { vaultId }, ipAddress, userAgent);
        return jsonResponse({ encryptedData });
    } catch (error: any) {
        console.error("Download vault error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_FAILURE', { vaultId, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while downloading vault data." }, 500);
    }
}

export async function handleDeleteVault(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const vaultIdParam = request.params?.vaultId;
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'VAULT_DELETE_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!vaultIdParam) {
        logAudit(env, ctx, user.userId, 'VAULT_DELETE_FAILURE', { reason: 'Missing vaultId' }, ipAddress, userAgent);
        return jsonResponse({ message: "Vault ID is required." }, 400);
    }

    const vaultId = parseInt(vaultIdParam);
    if (isNaN(vaultId)) {
        logAudit(env, ctx, user.userId, 'VAULT_DELETE_FAILURE', { vaultId: vaultIdParam, reason: 'Invalid vaultId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);
    }

    try {
        const vaultToDelete: VaultMetadata | null = await env.DB.prepare("SELECT r2_object_key, owner_id, owner_type FROM vaults WHERE id = ?").bind(vaultId).first();
        if (!vaultToDelete) {
            logAudit(env, ctx, user.userId, 'VAULT_DELETE_FAILURE', { vaultId, reason: 'Vault not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Vault not found." }, 404);
        }

        // Ensure the current user has 'manage' permission (already checked by middleware, but good to double-check logic)
        // The middleware `checkVaultPermission` for 'manage' should have already run.
        // This handler assumes permission is already verified.

        // D1 batch() ensures these two deletes are atomic
        await env.DB.batch([
            env.DB.prepare("DELETE FROM vault_access_controls WHERE vault_id = ?").bind(vaultId),
            env.DB.prepare("DELETE FROM vaults WHERE id = ?").bind(vaultId)
        ]);

        // Delete R2 object after DB records are removed
        await env.VAULTS.delete(vaultToDelete.r2_object_key);

        logAudit(env, ctx, user.userId, 'VAULT_DELETE_SUCCESS', { vaultId }, ipAddress, userAgent);
        return new Response(null, { status: 204 });
    } catch (error: any) {
        console.error("Delete vault error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_DELETE_FAILURE', { vaultId, error: error.message }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while deleting vault." }, 500);
    }
}