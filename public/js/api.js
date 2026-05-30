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

            if ((response.status === 401 || response.status === 403) && !suppressAuthRedirect) {
                clearSession();
                alert("Your session expired or you don't have access. Please log in again.");
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
export async function registerUser(email, masterPassword, encryptionSalt, turnstileToken) {
    return apiCall('/register', 'POST', {
        email,
        masterPassword,
        encryptionSalt,
        turnstileToken
    }, false); // No auth needed for registration
}

export async function loginUser(email, masterPassword, turnstileToken) {
    return apiCall('/login', 'POST', { email, masterPassword, turnstileToken }, false); // No auth needed for login
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

export async function enrollTotp(reauth = null) {
    return apiCall('/2fa/enroll', 'POST', reauth ?? {}, true, { suppressAuthRedirect: true });
}

export async function enableTotp(code) {
    return apiCall('/2fa/enable', 'POST', { code }, true, { suppressAuthRedirect: true });
}

export async function disableTotp(masterPassword, code) {
    return apiCall('/2fa/disable', 'POST', { masterPassword, code }, true, { suppressAuthRedirect: true });
}

export async function regenerateRecoveryCodes(masterPassword) {
    return apiCall('/2fa/recovery-codes/regenerate', 'POST', { masterPassword }, true, { suppressAuthRedirect: true });
}

export async function getUserEncryptionSalt(userId) {
    return apiCall(`/users/${userId}/encryption-salt`, 'GET');
}

export async function updateMasterPassword(userId, oldMasterPassword, newMasterPassword, newEncryptionSalt) {
    return apiCall(`/users/${userId}/update-password`, 'PUT', {
        oldMasterPassword,
        newMasterPassword,
        newEncryptionSalt
    });
}

// --- Vault Endpoints ---
export async function createVault(name, description, ownerId, ownerType, r2_object_key, initialPermissionLevel) {
    return apiCall('/vaults', 'POST', {
        name, description, ownerId, ownerType, r2_object_key, initialPermissionLevel
    });
}

export async function getVaults() {
    return apiCall('/vaults', 'GET');
}

export async function saveEncryptedVaultData(vaultId, encryptedData) {
    // encryptedData should be { iv: hexString, ciphertext: hexString }
    return apiCall(`/vaults/${vaultId}/data`, 'PUT', { encryptedData });
}

export async function loadEncryptedVaultData(vaultId) {
    // Returns { encryptedData: { iv: hexString, ciphertext: hexString } } or null if empty
    return apiCall(`/vaults/${vaultId}/data`, 'GET');
}

export async function deleteVault(vaultId) {
    return apiCall(`/vaults/${vaultId}`, 'DELETE');
}

export async function deleteAccount(userId, masterPassword) {
    return apiCall(`/users/${userId}`, 'DELETE', { masterPassword });
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
