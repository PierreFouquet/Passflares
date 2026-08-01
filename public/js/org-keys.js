// public/js/org-keys.js — keeping vault key shares in step with org membership.
//
// Membership and key access are separate facts. The server decides who is
// *allowed* to open an organisation vault; only someone who already holds the
// vault key can make that possible, because wrapping it for a new member
// requires the key itself — which the server has never seen.
//
// So every membership change has a client-side half:
//   add    -> wrap each org vault key for the newcomer
//   remove -> rotate each org vault key and re-wrap for whoever remains
//
// Both are best-effort by nature: they can only cover vaults the acting admin
// can currently open. Anything they can't reach is reported rather than hidden,
// so a partially-shared vault is visible instead of mysterious.

import { getVaults as apiGetVaults, getOrgMemberKeys, getUserPublicKey } from './api.js';
import { decryptVaultContents, rotateVaultKey, grantVaultKeyTo, orgIdOf } from './vault-keys.js';

/** Org-owned vaults this user can currently manage. */
async function manageableOrgVaults(orgId) {
    const vaults = await apiGetVaults();
    return vaults.filter(v =>
        v.owner_type === 'organization' &&
        orgIdOf(v) === orgId &&
        v.permission_level === 'manage'
    );
}

/**
 * Shares every org vault key this admin holds with a newly added member.
 *
 * @returns {Promise<{granted: number, pending: Array<string>}>}
 *   `pending` names vaults whose key could not be shared — the member is a
 *   member, but cannot open those until someone who can runs this again.
 */
export async function shareOrgVaultsWithNewMember(orgId, memberUserId) {
    const { publicKey } = await getUserPublicKey(memberUserId);
    if (!publicKey) {
        // They have never signed in since the key hierarchy shipped, so there is
        // nothing to wrap to yet.
        return { granted: 0, pending: [], notUpgraded: true };
    }

    const vaults = await manageableOrgVaults(orgId);
    let granted = 0;
    const pending = [];

    for (const vault of vaults) {
        try {
            const { vaultKey } = await decryptVaultContents(vault);
            if (!vaultKey) { pending.push(vault.name); continue; }
            await grantVaultKeyTo(vault.id, vaultKey, { userId: memberUserId, publicKey });
            granted++;
        } catch {
            pending.push(vault.name);
        }
    }

    return { granted, pending, notUpgraded: false };
}

/**
 * Rotates the key of every org vault the removed member could reach, and
 * re-wraps it for the remaining members.
 *
 * Deleting their share (which the server does) stops them fetching the key
 * again, but revocation has to assume they already cached it — so the key has to
 * actually change and the contents be re-encrypted under the new one.
 *
 * @returns {Promise<{rotated: number, failed: Array<string>}>}
 */
export async function rotateOrgVaultsAfterRemoval(orgId, vaultIds) {
    if (!vaultIds || vaultIds.length === 0) return { rotated: 0, failed: [] };

    const manageable = await manageableOrgVaults(orgId);
    const targets = manageable.filter(v => vaultIds.includes(v.id));

    const { members } = await getOrgMemberKeys(orgId);
    const remaining = members
        .filter(m => m.publicKey)
        .map(m => ({ userId: m.userId, publicKey: m.publicKey }));

    let rotated = 0;
    const failed = [];

    for (const vault of targets) {
        try {
            const { entries } = await decryptVaultContents(vault);
            await rotateVaultKey(vault, entries, remaining);
            rotated++;
        } catch {
            // We couldn't open it, so we can't rotate it. The removed member's
            // share is already gone; the stale-key risk stands until an admin
            // who can open it does this.
            failed.push(vault.name);
        }
    }

    return { rotated, failed };
}
