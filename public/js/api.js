// public/js/api.js

import { API_BASE_URL } from './constants.js';
import { getAuthHeaders, clearSession } from './session.js';

/**
 * Makes an authenticated API call to the backend Worker.
 * @param {string} endpoint The API endpoint (e.g., '/register', '/vaults').
 * @param {string} method HTTP method (GET, POST, PUT, DELETE).
 * @param {Object} [data=null] Request body data.
 * @param {boolean} [needsAuth=true] Whether the request requires an authentication token.
 * @returns {Promise<Object|null>} JSON response from the API or null for 204 No Content.
 * @throws {Error} If the API call fails.
 */
export async function apiCall(endpoint, method = 'GET', data = null, needsAuth = true, { suppressAuthRedirect = false } = {}) {
    const headers = needsAuth
        ? getAuthHeaders()
        : { 'Content-Type': 'application/json' };

    const config = { method, headers };

    if (data) {
        config.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

        if (!response.ok) {
            const errorBody = await response.text();
            let errorMessage = `API Error (${response.status}): ${response.statusText}`;
            try {
                const errorJson = JSON.parse(errorBody);
                errorMessage = errorJson.message || errorJson.error || errorMessage;
            } catch (parseError) {
                // If it's not JSON, use the raw text
                errorMessage += ` - ${errorBody}`;
            }
            console.error(`Error during ${method} ${endpoint}:`, errorBody);

            // Only a 401 means the session itself is invalid/expired — re-auth
            // in that case. A 403 means the request was authenticated but not
            // permitted (e.g. acting on a resource you lack rights to); surface
            // it as an error rather than destroying a still-valid session, so a
            // permission denial never masquerades as a forced logout.
            if (response.status === 401 && !suppressAuthRedirect) {
                clearSession();
                alert("Your session has expired. Please log in again.");
                window.location.reload(); // Force refresh to re-render login
            }
            throw new Error(errorMessage);
        }

        if (response.status === 204) {
            return null; // No content
        }

        return await response.json();
    } catch (error) {
        console.error("Fetch API call failed:", error);
        throw error; // Re-throw to be caught by calling function
    }
}

// --- Auth Endpoints ---
//
// Note what is absent from every call below: the master password. Under
// auth_version 2 the browser derives an Argon2id master key locally and sends
// only `authSecret = HKDF(masterKey, "auth")`, which cannot produce the key that
// decrypts vault contents. The single exception is loginUser's legacy branch,
// used once per unmigrated account so it can be upgraded.

/**
 * Which authentication flow this email needs, plus the Argon2id inputs for it.
 * Returns plausible decoy parameters for unknown emails, so a caller cannot use
 * it to test whether an account exists.
 */
export async function getAuthParams(email) {
    return apiCall(`/auth/params?email=${encodeURIComponent(email)}`, 'GET', null, false);
}

export async function registerUser({ email, authSecret, kdfSalt, kdfParams, publicKey, privateKeyEnc, turnstileToken }) {
    return apiCall('/register', 'POST', {
        email, authSecret, kdfSalt, kdfParams, publicKey, privateKeyEnc, turnstileToken
    }, false); // No auth needed for registration
}

export async function loginUser(email, credentials, turnstileToken) {
    // credentials is { authSecret } for v2 and { masterPassword } for legacy
    // accounts that have not been upgraded yet.
    return apiCall('/login', 'POST', { email, ...credentials, turnstileToken }, false);
}

/**
 * One-shot auth_version 1 -> 2 upgrade. Everything the server needs arrives in a
 * single request so it can be applied in one D1 batch — either the account is
 * fully migrated or entirely untouched.
 */
export async function upgradeAccount(payload) {
    return apiCall('/auth/upgrade', 'POST', payload);
}

// Second login step: exchange the temp token + a TOTP/recovery code for a real
// session. suppressAuthRedirect so a wrong code's 401 doesn't wipe the dialog.
export async function verifyLogin2fa(tempToken, code) {
    return apiCall('/login/2fa', 'POST', { tempToken, code }, false, { suppressAuthRedirect: true });
}

// --- Two-factor (TOTP) endpoints ---
export async function getTotpStatus() {
    return apiCall('/2fa/status', 'GET');
}

/**
 * The signed-in account's own audit events, newest first.
 *
 * `before` is the previous page's `nextBefore` — keyset pagination, so pages
 * stay stable as new events arrive rather than shifting under an offset.
 */
export async function getAuditLog({ limit = 25, before = null } = {}) {
    const params = new URLSearchParams({ limit: String(limit) });
    if (before) params.set('before', before);
    return apiCall(`/users/me/audit-log?${params}`, 'GET');
}

export async function enrollTotp(reauth = null) {
    return apiCall('/2fa/enroll', 'POST', reauth ?? {}, true, { suppressAuthRedirect: true });
}

export async function enableTotp(code) {
    return apiCall('/2fa/enable', 'POST', { code }, true, { suppressAuthRedirect: true });
}

export async function disableTotp(authSecret, code) {
    return apiCall('/2fa/disable', 'POST', { authSecret, code }, true, { suppressAuthRedirect: true });
}

export async function regenerateRecoveryCodes(authSecret) {
    return apiCall('/2fa/recovery-codes/regenerate', 'POST', { authSecret }, true, { suppressAuthRedirect: true });
}

export async function getUserEncryptionSalt(userId) {
    return apiCall(`/users/${userId}/encryption-salt`, 'GET');
}

/** A member's public key, so a vault key can be wrapped for them. */
export async function getUserPublicKey(userId) {
    return apiCall(`/users/${userId}/public-key`, 'GET');
}

/**
 * Rotating the master password re-derives the Argon2id salt, the auth verifier
 * and the wrapped private key. Vault ciphertext is untouched — which is what
 * removes the data-loss window in #70.
 */
export async function updateMasterPassword(userId, payload) {
    return apiCall(`/users/${userId}/update-password`, 'PUT', payload);
}

// --- Vault Endpoints ---
export async function createVault(name, description, ownerId, ownerType, initialPermissionLevel, keyShare) {
    return apiCall('/vaults', 'POST', {
        name, description, ownerId, ownerType, initialPermissionLevel, keyShare
    });
}

export async function getVaults() {
    return apiCall('/vaults', 'GET');
}

/**
 * @param {string} [keyVersion] When it differs from the vault's live version the
 *   blob is *staged* beside the current one rather than replacing it, and only
 *   goes live once commitKeyVersions() succeeds. That two-step is what makes
 *   re-encryption non-destructive (#70).
 */
export async function saveEncryptedVaultData(vaultId, encryptedData, keyVersion) {
    // encryptedData should be { iv: hexString, ciphertext: hexString }
    return apiCall(`/vaults/${vaultId}/data`, 'PUT', { encryptedData, keyVersion });
}

/** Promotes staged blobs to live for several vaults in one atomic server batch. */
export async function commitKeyVersions(vaults) {
    return apiCall('/vaults/key-version/commit', 'POST', { vaults });
}

export async function loadEncryptedVaultData(vaultId) {
    // Returns { encryptedData: { iv: hexString, ciphertext: hexString } } or null if empty
    return apiCall(`/vaults/${vaultId}/data`, 'GET');
}

/** This user's wrapped copy of a vault key; { share: null } if none was granted. */
export async function getVaultKeyShare(vaultId) {
    return apiCall(`/vaults/${vaultId}/share`, 'GET');
}

/** Grants (or, with replace, rotates) the set of members holding a vault key. */
export async function putVaultKeyShares(vaultId, shares, { replace = false, keyVersion = 'v2' } = {}) {
    return apiCall(`/vaults/${vaultId}/shares`, 'PUT', { shares, replace, keyVersion });
}

export async function deleteVault(vaultId) {
    return apiCall(`/vaults/${vaultId}`, 'DELETE');
}

export async function deleteAccount(userId, authSecret) {
    return apiCall(`/users/${userId}`, 'DELETE', { authSecret });
}

// --- Organization Endpoints ---
export async function createOrganization(name, description) {
    return apiCall('/organizations', 'POST', { name, description });
}

export async function getOrganizations() {
    return apiCall('/organizations', 'GET');
}

export async function addMemberToOrganization(orgId, memberEmail, role) {
    return apiCall(`/organizations/${orgId}/members`, 'POST', { memberEmail, role });
}

export async function getOrgMembers(orgId) {
    return apiCall(`/organizations/${orgId}/members`, 'GET');
}

/**
 * Every member's public key in one call, so an admin holding a vault key can
 * wrap it for the whole organisation without a round trip per member.
 * `publicKey: null` marks a member who hasn't upgraded yet.
 */
export async function getOrgMemberKeys(orgId) {
    return apiCall(`/organizations/${orgId}/member-keys`, 'GET');
}

/**
 * Members entitled to an org vault who hold no wrapped copy of its key.
 *
 * Entitlement metadata only — no key material. Feeds reconcileOrgVaultKeys(),
 * which closes the gaps this caller can reach.
 */
export async function getOrgKeyGaps(orgId) {
    return apiCall(`/organizations/${orgId}/key-gaps`, 'GET');
}

export async function updateMemberRole(orgId, userId, role) {
    return apiCall(`/organizations/${orgId}/members/${userId}`, 'PUT', { role });
}

export async function removeMember(orgId, userId) {
    return apiCall(`/organizations/${orgId}/members/${userId}`, 'DELETE');
}

export async function deleteOrganization(orgId) {
    return apiCall(`/organizations/${orgId}`, 'DELETE');
}

// --- Preference Endpoints ---
export async function getPreferences() {
    return apiCall('/users/me/preferences', 'GET');
}

export async function updatePreferences(partial) {
    return apiCall('/users/me/preferences', 'PUT', partial);
}
