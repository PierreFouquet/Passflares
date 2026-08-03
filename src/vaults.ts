// src/vaults.ts

import {
    CustomRequest, Env, VaultMetadata, EncryptedVaultBlob, OrgRole, ADMIN_ROLES,
    versionedObjectKey, VALID_KEY_VERSIONS
} from './types.js';
import { logAudit } from './auditLog.js';
import {
    jsonResponse,
    parseId,
    safeJson,
    auditErrorCode,
    isSaneText,
    MAX_NAME_LENGTH,
    MAX_DESCRIPTION_LENGTH
} from './utils.js';
import { resolveVaultAccess, permissionSatisfies } from './middleware.js';

// Note on the SELECT lists below: r2_object_key is deliberately never returned
// to clients. It is an internal storage identifier nothing client-side addresses
// anything by (every vault operation goes through /api/vaults/:id), and it leaks
// the user_N/org_N owner prefix plus a UUID for no benefit (#80).

export async function handleCreateVault(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const body = await safeJson<{
        name?: string;
        description?: string;
        ownerId?: string; // 'user_X' or 'org_Y'
        ownerType?: 'user' | 'organization';
        initialPermissionLevel?: 'read' | 'write' | 'manage';
    }>(request);
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!body) {
        return jsonResponse({ message: "Invalid JSON body." }, 400);
    }
    const { name, description, ownerId, ownerType, initialPermissionLevel } = body;

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'VAULT_CREATE_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!name || !ownerId || !ownerType || !initialPermissionLevel) {
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Missing fields' }, ipAddress, userAgent);
        return jsonResponse({ message: "Vault name, owner ID, owner type, and initial permission are required." }, 400);
    }
    // Nothing bounded these before they reached D1 (#78).
    if (!isSaneText(name, MAX_NAME_LENGTH) || !isSaneText(description, MAX_DESCRIPTION_LENGTH) ||
        !isSaneText(ownerId, 64)) {
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Field too long' }, ipAddress, userAgent);
        return jsonResponse({
            message: `Vault name must be at most ${MAX_NAME_LENGTH} characters and the description at most ${MAX_DESCRIPTION_LENGTH}.`
        }, 400);
    }
    if (!['user', 'organization'].includes(ownerType)) {
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Invalid owner type', ownerType }, ipAddress, userAgent);
        return jsonResponse({ message: "Invalid owner type." }, 400);
    }
    if (!['read', 'write', 'manage'].includes(initialPermissionLevel)) {
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Invalid permission level', initialPermissionLevel }, ipAddress, userAgent);
        return jsonResponse({ message: "Invalid initial permission level." }, 400);
    }
    // Note: no key share arrives with this request. A vault key is wrapped with
    // the vault's id as the ECIES binding (so a share can't be replayed onto
    // another vault), and that id doesn't exist until the row below is inserted.
    // The client therefore creates, then immediately PUTs its share — and
    // deletes the vault if that second call fails, so no unopenable vault is
    // left behind. The window is harmless: the vault is empty throughout.

    try {
        // Validate ownerId based on ownerType
        if (ownerType === 'user' && ownerId !== `user_${user.userId}`) {
            logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { reason: 'Unauthorized user owner ID' }, ipAddress, userAgent);
            return jsonResponse({ message: "Unauthorized: Cannot create vault for another user." }, 403);
        } else if (ownerType === 'organization') {
            const orgId = parseId(ownerId.split('_')[1]);
            if (orgId === null) {
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
        // New vaults are born under the key hierarchy — their contents are
        // encrypted with a random per-vault key, not anything password-derived.
        const currentKeyVersion = 'v2';

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
            current_key_version: currentKeyVersion
        }, 201);
    } catch (error: any) {
        console.error("Create vault error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_CREATE_FAILURE', { name, ownerId, ownerType, error: auditErrorCode(error) }, ipAddress, userAgent);
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
            `SELECT v.id, v.name, v.description, v.owner_id, v.owner_type, v.current_key_version,
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
            `SELECT v.id, v.name, v.description, v.owner_id, v.owner_type, v.current_key_version,
                    vac.permission_level
             FROM vaults v
             JOIN vault_access_controls vac ON v.id = vac.vault_id
             JOIN user_organizations uo ON vac.entity_id = 'org_' || uo.organization_id AND vac.entity_type = 'organization'
             WHERE uo.user_id = ?`
        )
            .bind(user.userId)
            .all()
            .then(res => res.results as unknown as VaultMetadata[]);

        // Which of those the user actually holds a key for. Permission and
        // decryptability are independent: an org admin can be authorised to open
        // a vault and still lack a key share, which is exactly the confusing
        // state #69 describes. Reporting it lets the UI say so honestly.
        const shareRows = await env.DB.prepare(
            "SELECT vault_id FROM vault_key_shares WHERE user_id = ?"
        ).bind(user.userId).all().then(r => r.results as unknown as { vault_id: number }[]);
        const heldKeys = new Set(shareRows.map(r => r.vault_id));

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

        const distinctVaults = Array.from(allVaultsMap.values())
            .map(v => ({ ...v, has_key_share: heldKeys.has(v.id) }));

        // No VAULT_LIST_SUCCESS row: main.js prefetches vaults on every app boot,
        // so this fired before the user had done anything (#73).
        return jsonResponse(distinctVaults);
    } catch (error: any) {
        console.error("Get vaults error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_LIST_FAILURE', { error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while fetching vaults." }, 500);
    }
}

/**
 * PUT /api/vaults/:vaultId/data
 *
 * Writing to a key version other than the vault's current one stages the blob
 * beside the live one rather than replacing it — nothing the client can do here
 * destroys readable data. The staged blob only becomes live when
 * handleCommitKeyVersion flips vaults.current_key_version.
 *
 * That two-step is what closes #70: previously this overwrote in place, so an
 * interrupted re-encryption left R2 holding ciphertext under a key D1 had never
 * heard of.
 */
export async function handleUploadVault(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const vaultIdParam = request.params?.vaultId;
    const body = await safeJson<{
        encryptedData?: EncryptedVaultBlob;
        keyVersion?: string;
    }>(request);
    const user = request.user;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    if (!body) {
        return jsonResponse({ message: "Invalid JSON body." }, 400);
    }
    const { encryptedData, keyVersion } = body;

    if (!user || !user.userId) {
        logAudit(env, ctx, null, 'VAULT_UPLOAD_FAILURE', { reason: 'Unauthorized' }, ipAddress, userAgent);
        return jsonResponse({ message: "Unauthorized." }, 401);
    }
    if (!vaultIdParam || !encryptedData || !encryptedData.iv || !encryptedData.ciphertext) {
        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { reason: 'Missing fields', vaultId: vaultIdParam }, ipAddress, userAgent);
        return jsonResponse({ message: "Vault ID and encrypted data (IV, ciphertext) are required." }, 400);
    }

    const vaultId = parseId(vaultIdParam);
    if (vaultId === null) {
        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { vaultId: vaultIdParam, reason: 'Invalid vaultId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);
    }
    if (keyVersion !== undefined && !VALID_KEY_VERSIONS.includes(keyVersion)) {
        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { vaultId, reason: 'Invalid key version', keyVersion }, ipAddress, userAgent);
        return jsonResponse({ message: "Unsupported key version." }, 400);
    }

    try {
        const vault = await env.DB.prepare(
            "SELECT r2_object_key, current_key_version FROM vaults WHERE id = ?"
        ).bind(vaultId).first<Pick<VaultMetadata, 'r2_object_key' | 'current_key_version'>>();
        if (!vault) {
            logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { vaultId, reason: 'Vault not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Vault not found." }, 404);
        }

        const targetVersion = keyVersion ?? vault.current_key_version ?? 'v1';
        const objectKey = versionedObjectKey(vault.r2_object_key, targetVersion);
        await env.VAULTS.put(objectKey, JSON.stringify(encryptedData));

        const staged = targetVersion !== (vault.current_key_version ?? 'v1');
        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_SUCCESS', { vaultId, keyVersion: targetVersion, staged }, ipAddress, userAgent);
        // 200 with a body when staging, so the client knows the write is not yet
        // live and a commit is still owed; 204 for a plain in-place save.
        return staged
            ? jsonResponse({ message: "Staged.", keyVersion: targetVersion, staged: true })
            : new Response(null, { status: 204 });
    } catch (error: any) {
        console.error("Upload vault error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_UPLOAD_FAILURE', { vaultId, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while uploading vault data." }, 500);
    }
}

/**
 * POST /api/vaults/key-version/commit
 *
 * Atomically promotes staged blobs to live for a set of vaults. Every vault is
 * permission-checked before anything is written, and the flips go through one
 * D1.batch() — so a re-encryption either takes effect everywhere or nowhere.
 *
 * Superseded blobs are swept afterwards; a sweep failure is harmless (an orphan
 * object) whereas failing the request after a successful commit would not be.
 */
export async function handleCommitKeyVersion(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const user = request.user!;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');

    const body = await safeJson<{
        vaults?: Array<{ vaultId: number; keyVersion: string }>;
    }>(request);
    if (!body) {
        return jsonResponse({ message: "Invalid JSON body." }, 400);
    }
    const { vaults } = body;

    if (!Array.isArray(vaults) || vaults.length === 0) {
        return jsonResponse({ message: "A non-empty list of vaults is required." }, 400);
    }
    for (const entry of vaults) {
        if (!Number.isInteger(entry?.vaultId) || entry.vaultId <= 0 || !VALID_KEY_VERSIONS.includes(entry?.keyVersion)) {
            return jsonResponse({ message: "Each entry needs a valid vaultId and keyVersion." }, 400);
        }
    }

    try {
        // Check everything before mutating anything — a partial commit is the
        // exact failure this endpoint exists to prevent.
        const previous = new Map<number, string>();
        for (const { vaultId } of vaults) {
            const access = await resolveVaultAccess(env, user.userId, vaultId);
            if (!access || !permissionSatisfies(access, 'write')) {
                logAudit(env, ctx, user.userId, 'VAULT_KEY_COMMIT_FAILURE', { vaultId, reason: 'Insufficient permission' }, ipAddress, userAgent);
                return jsonResponse({ message: `Forbidden: no write access to vault ${vaultId}.` }, 403);
            }
            const row = await env.DB.prepare(
                "SELECT r2_object_key, current_key_version FROM vaults WHERE id = ?"
            ).bind(vaultId).first<Pick<VaultMetadata, 'r2_object_key' | 'current_key_version'>>();
            if (!row) return jsonResponse({ message: `Vault ${vaultId} not found.` }, 404);
            previous.set(vaultId, versionedObjectKey(row.r2_object_key, row.current_key_version ?? 'v1'));
        }

        const update = env.DB.prepare("UPDATE vaults SET current_key_version = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
        await env.DB.batch(vaults.map(v => update.bind(v.keyVersion, v.vaultId)));

        // Sweep the superseded blobs now that the new ones are authoritative.
        for (const { vaultId, keyVersion } of vaults) {
            const oldKey = previous.get(vaultId)!;
            const newKeyRow = await env.DB.prepare("SELECT r2_object_key FROM vaults WHERE id = ?")
                .bind(vaultId).first<{ r2_object_key: string }>();
            const newKey = versionedObjectKey(newKeyRow!.r2_object_key, keyVersion);
            if (oldKey !== newKey) {
                try {
                    await env.VAULTS.delete(oldKey);
                } catch (sweepError) {
                    console.error(`Failed to sweep superseded blob for vault ${vaultId}:`, sweepError);
                }
            }
        }

        logAudit(env, ctx, user.userId, 'VAULT_KEY_COMMIT_SUCCESS', { vaultIds: vaults.map(v => v.vaultId) }, ipAddress, userAgent);
        return jsonResponse({ message: "Key versions committed.", committed: vaults.length });
    } catch (error: any) {
        console.error("Commit key version error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_KEY_COMMIT_FAILURE', { error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while committing key versions." }, 500);
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

    const vaultId = parseId(vaultIdParam);
    if (vaultId === null) {
        logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_FAILURE', { vaultId: vaultIdParam, reason: 'Invalid vaultId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);
    }

    try {
        const vault = await env.DB.prepare(
            "SELECT r2_object_key, current_key_version FROM vaults WHERE id = ?"
        ).bind(vaultId).first<Pick<VaultMetadata, 'r2_object_key' | 'current_key_version'>>();
        if (!vault) {
            logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_FAILURE', { vaultId, reason: 'Vault not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Vault not found." }, 404);
        }

        const keyVersion = vault.current_key_version ?? 'v1';
        const object = await env.VAULTS.get(versionedObjectKey(vault.r2_object_key, keyVersion));
        if (object === null) {
            // If the R2 object doesn't exist, it means the vault is new/empty
            return new Response(null, { status: 204 }); // 204 No Content for empty vault
        }

        // R2 object content is usually a ReadableStream or ArrayBuffer
        const encryptedData: EncryptedVaultBlob = await object.json();

        // No VAULT_DOWNLOAD_SUCCESS row: one per vault open, on a table with no
        // retention (#73). VAULT_DOWNLOAD_FAILURE and VAULT_ACCESS_DENIED —
        // the security-relevant halves — are still recorded.
        return jsonResponse({ encryptedData, keyVersion });
    } catch (error: any) {
        console.error("Download vault error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_DOWNLOAD_FAILURE', { vaultId, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while downloading vault data." }, 500);
    }
}

/**
 * GET /api/vaults/:vaultId/share
 *
 * The caller's own wrapped copy of the vault key. Useless to anyone else — it
 * only opens with the private key that never leaves their browser.
 */
export async function handleGetVaultShare(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const user = request.user!;
    const vaultId = parseId(request.params?.vaultId);
    if (vaultId === null) return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);

    try {
        const share = await env.DB.prepare(
            "SELECT wrapped_key, ephemeral_pubkey, key_version FROM vault_key_shares WHERE vault_id = ? AND user_id = ?"
        ).bind(vaultId, user.userId).first<{ wrapped_key: string; ephemeral_pubkey: string; key_version: string }>();

        if (!share) {
            // Authorised but keyless. The client must say "an admin hasn't shared
            // the key with you yet", not "check your password" (#69).
            return jsonResponse({ share: null, reason: 'no_key_share' }, 200);
        }
        return jsonResponse({ share });
    } catch (error: any) {
        console.error("Get vault share error:", error);
        return jsonResponse({ message: "Internal Server Error while fetching the vault key." }, 500);
    }
}

/**
 * PUT /api/vaults/:vaultId/shares
 *
 * Replaces the set of members holding this vault's key. Requires `manage`, since
 * it is the grant/revoke primitive.
 *
 * The server can only shuffle opaque ciphertext here: it cannot verify that a
 * wrapped key is well-formed or that it wraps the right vault key, because
 * checking would require the plaintext key — which is the whole point. What it
 * *can* enforce is that every recipient is genuinely entitled to the vault, so a
 * caller cannot quietly hand a key to an outsider.
 */
export async function handlePutVaultShares(request: CustomRequest, env: Env, ctx: ExecutionContext): Promise<Response> {
    const user = request.user!;
    const ipAddress = request.headers.get('CF-Connecting-IP');
    const userAgent = request.headers.get('User-Agent');
    const vaultId = parseId(request.params?.vaultId);
    if (vaultId === null) return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);

    const body = await safeJson<{
        shares?: Array<{ userId: number; wrappedKey: string; ephemeralPubkey: string }>;
        keyVersion?: string;
        replace?: boolean;
    }>(request);
    if (!body) {
        return jsonResponse({ message: "Invalid JSON body." }, 400);
    }
    const { shares, keyVersion, replace } = body;

    if (!Array.isArray(shares) || shares.length === 0) {
        return jsonResponse({ message: "A non-empty list of key shares is required." }, 400);
    }
    if (keyVersion !== undefined && !VALID_KEY_VERSIONS.includes(keyVersion)) {
        return jsonResponse({ message: "Unsupported key version." }, 400);
    }
    for (const share of shares) {
        if (!Number.isInteger(share?.userId) || share.userId <= 0 ||
            typeof share?.wrappedKey !== 'string' || share.wrappedKey.length === 0 || share.wrappedKey.length > 4096 ||
            typeof share?.ephemeralPubkey !== 'string' || share.ephemeralPubkey.length === 0 || share.ephemeralPubkey.length > 1024) {
            return jsonResponse({ message: "Each share needs a userId, wrappedKey and ephemeralPubkey." }, 400);
        }
    }

    try {
        // Every recipient must independently have access to this vault. Without
        // this check, "manage" on a vault would let someone mint a key share for
        // an arbitrary account.
        for (const share of shares) {
            const access = await resolveVaultAccess(env, share.userId, vaultId);
            if (!access) {
                logAudit(env, ctx, user.userId, 'VAULT_SHARE_FAILURE',
                    { vaultId, recipient: share.userId, reason: 'Recipient has no vault access' }, ipAddress, userAgent);
                return jsonResponse({ message: `User ${share.userId} does not have access to this vault.` }, 403);
            }
        }

        const version = keyVersion ?? 'v2';
        const statements = [];

        // On a rotation the old shares must go, or a removed member keeps a row
        // that still unwraps the previous key.
        if (replace) {
            statements.push(env.DB.prepare("DELETE FROM vault_key_shares WHERE vault_id = ?").bind(vaultId));
        }

        const insert = env.DB.prepare(
            `INSERT INTO vault_key_shares (vault_id, user_id, wrapped_key, ephemeral_pubkey, key_version, created_by)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(vault_id, user_id) DO UPDATE SET wrapped_key = excluded.wrapped_key,
                 ephemeral_pubkey = excluded.ephemeral_pubkey, key_version = excluded.key_version,
                 created_by = excluded.created_by`
        );
        for (const share of shares) {
            statements.push(insert.bind(vaultId, share.userId, share.wrappedKey, share.ephemeralPubkey, version, user.userId));
        }

        await env.DB.batch(statements);

        logAudit(env, ctx, user.userId, 'VAULT_SHARE_SUCCESS',
            { vaultId, recipients: shares.map(s => s.userId), replace: !!replace }, ipAddress, userAgent);
        return jsonResponse({ message: "Vault key shares updated.", count: shares.length });
    } catch (error: any) {
        console.error("Put vault shares error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_SHARE_FAILURE', { vaultId, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while updating vault key shares." }, 500);
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

    const vaultId = parseId(vaultIdParam);
    if (vaultId === null) {
        logAudit(env, ctx, user.userId, 'VAULT_DELETE_FAILURE', { vaultId: vaultIdParam, reason: 'Invalid vaultId format' }, ipAddress, userAgent);
        return jsonResponse({ message: "Bad Request: Invalid vault ID format." }, 400);
    }

    try {
        const vaultToDelete = await env.DB.prepare(
            "SELECT r2_object_key, owner_id, owner_type, current_key_version FROM vaults WHERE id = ?"
        ).bind(vaultId).first<Pick<VaultMetadata, 'r2_object_key' | 'owner_id' | 'owner_type' | 'current_key_version'>>();
        if (!vaultToDelete) {
            logAudit(env, ctx, user.userId, 'VAULT_DELETE_FAILURE', { vaultId, reason: 'Vault not found' }, ipAddress, userAgent);
            return jsonResponse({ message: "Vault not found." }, 404);
        }

        // Ensure the current user has 'manage' permission (already checked by middleware, but good to double-check logic)
        // The middleware `checkVaultPermission` for 'manage' should have already run.
        // This handler assumes permission is already verified.

        // D1 batch() ensures these deletes are atomic
        await env.DB.batch([
            env.DB.prepare("DELETE FROM vault_access_controls WHERE vault_id = ?").bind(vaultId),
            env.DB.prepare("DELETE FROM vault_key_shares WHERE vault_id = ?").bind(vaultId),
            env.DB.prepare("DELETE FROM vaults WHERE id = ?").bind(vaultId)
        ]);

        // Delete every key version's object after DB records are removed. A
        // migrated vault may still have its superseded blob if the sweep failed.
        for (const version of VALID_KEY_VERSIONS) {
            const key = versionedObjectKey(vaultToDelete.r2_object_key, version);
            try {
                await env.VAULTS.delete(key);
            } catch (deleteError) {
                console.error(`Failed to delete R2 object ${key}:`, deleteError);
            }
        }

        logAudit(env, ctx, user.userId, 'VAULT_DELETE_SUCCESS', { vaultId }, ipAddress, userAgent);
        return new Response(null, { status: 204 });
    } catch (error: any) {
        console.error("Delete vault error:", error);
        logAudit(env, ctx, user.userId, 'VAULT_DELETE_FAILURE', { vaultId, error: auditErrorCode(error) }, ipAddress, userAgent);
        return jsonResponse({ message: "Internal Server Error while deleting vault." }, 500);
    }
}
