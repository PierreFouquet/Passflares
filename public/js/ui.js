// public/js/ui.js

// --- Element References ---
export const authSection = document.getElementById('auth-section');
export const appSection = document.getElementById('app-section');

export const loginTab = document.getElementById('login-tab');
export const registerTab = document.getElementById('register-tab');
export const loginForm = document.getElementById('login-form');
export const registerForm = document.getElementById('register-form');
export const authMessage = document.getElementById('auth-message');

export const loginEmailInput = document.getElementById('login-email');
export const loginMasterPasswordInput = document.getElementById('login-master-password');
export const registerEmailInput = document.getElementById('register-email');
export const registerMasterPasswordInput = document.getElementById('register-master-password');
export const registerConfirmMasterPasswordInput = document.getElementById('register-confirm-master-password');
export const passwordStrengthText = document.getElementById('password-strength-text');

export const userEmailDisplay = document.getElementById('user-email-display');
export const logoutButton = document.getElementById('logout-button');

export const vaultsSection = document.getElementById('vaults-section');
export const newVaultNameInput = document.getElementById('new-vault-name');
export const newVaultDescriptionInput = document.getElementById('new-vault-description');
export const newVaultOwnerTypeSelect = document.getElementById('new-vault-owner-type');
export const organizationSelectionDiv = document.getElementById('organization-selection');
export const selectOrganizationDropdown = document.getElementById('select-organization');
export const createOrganizationButton = document.getElementById('create-organization-button');
export const createVaultButton = document.getElementById('create-vault-button');
export const vaultsListDiv = document.getElementById('vaults-list');
export const vaultMessage = document.getElementById('vault-message');

export const vaultDetailsSection = document.getElementById('vault-details-section');
export const currentVaultName = document.getElementById('current-vault-name');
export const currentVaultDescription = document.getElementById('current-vault-description');
export const deleteCurrentVaultButton = document.getElementById('delete-current-vault-button');
export const loadAnotherVaultButton = document.getElementById('load-another-vault-button');

export const addEntryForm = document.getElementById('add-entry-form');
export const entryNameInput = document.getElementById('entry-name');
export const entryUsernameInput = document.getElementById('entry-username');
export const entryPasswordInput = document.getElementById('entry-password');
export const generatePasswordButton = document.getElementById('generate-password-button');
export const entryUrlInput = document.getElementById('entry-url');
export const entryNotesInput = document.getElementById('entry-notes');
export const entriesListDiv = document.getElementById('entries-list');
export const saveVaultDataButton = document.getElementById('save-vault-data-button');
export const entryMessage = document.getElementById('entry-message');
export const searchEntriesInput = document.getElementById('search-entries');
export const searchButton = document.getElementById('search-button');
export const clearSearchButton = document.getElementById('clear-search-button');

export const changeMasterPasswordButton = document.getElementById('change-master-password-button');
export const changeMasterPasswordModal = document.getElementById('change-master-password-modal');
export const changeMasterPasswordForm = document.getElementById('change-master-password-form');
export const oldMasterPasswordInput = document.getElementById('old-master-password');
export const newMasterPasswordInput = document.getElementById('new-master-password');
export const confirmNewMasterPasswordInput = document.getElementById('confirm-new-master-password');
export const newPasswordStrengthText = document.getElementById('new-password-strength-text');
export const changePasswordMessage = document.getElementById('change-password-message');
export const exportVaultDataButton = document.getElementById('export-vault-data-button');

// Organization Modals
export const createOrganizationModal = document.getElementById('create-organization-modal');
export const orgNameInput = document.getElementById('org-name-input');
export const orgDescriptionInput = document.getElementById('org-description-input');
export const submitCreateOrgButton = document.getElementById('submit-create-org');
export const orgModalMessage = document.getElementById('org-modal-message');

export const addOrgMemberModal = document.getElementById('add-org-member-modal');
export const addMemberOrgName = document.getElementById('add-member-org-name');
export const memberEmailInput = document.getElementById('member-email-input');
export const memberRoleSelect = document.getElementById('member-role-select');
export const submitAddMemberButton = document.getElementById('submit-add-member');
export const addMemberModalMessage = document.getElementById('add-member-modal-message');


// Loading Overlay
export const loadingOverlay = document.getElementById('loading-overlay');
export const loadingText = document.getElementById('loading-text');

// --- General UI Functions ---

export function showElement(element) {
    element.classList.remove('hidden');
}

export function hideElement(element) {
    element.classList.add('hidden');
}

export function showMessage(element, message, type = 'info') {
    element.textContent = message;
    element.className = `message ${type}`; // 'message success', 'message error', 'message info'
    showElement(element);
}

export function clearForm(formElement) {
    formElement.reset();
    const messageElement = formElement.querySelector('.message');
    if (messageElement) {
        hideElement(messageElement);
    }
    // Clear password strength indicator if present
    const strengthSpan = formElement.querySelector('.password-strength span');
    if (strengthSpan) {
        strengthSpan.textContent = 'N/A';
        strengthSpan.style.color = '';
    }
}

export function populateVaultsList(vaults, onVaultLoad, onVaultManage, onVaultDelete) {
    vaultsListDiv.innerHTML = '';
    if (vaults.length === 0) {
        vaultsListDiv.innerHTML = '<p class="no-entries-message">No vaults found. Create one above!</p>';
        return;
    }

    vaults.forEach(vault => {
        const vaultItem = document.createElement('div');
        vaultItem.className = 'vault-item';
        vaultItem.innerHTML = `
            <h3>${escapeHTML(vault.name)}</h3>
            <p>${escapeHTML(vault.description || 'No description.')}</p>
            <p class="small-text">Owner: ${vault.owner_type === 'user' ? 'You' : `Organization ID: ${vault.owner_id.split('_')[1]}`}</p>
            <p class="small-text">Your Access: <strong>${vault.permission_level}</strong></p>
            <div class="buttons">
                <button class="load-vault-btn" data-vault-id="${vault.id}" data-vault-name="${escapeHTML(vault.name)}" data-vault-description="${escapeHTML(vault.description || '')}" data-r2-key="${escapeHTML(vault.r2_object_key)}">Load</button>
                ${vault.permission_level === 'manage' ? `<button class="manage-vault-btn" data-vault-id="${vault.id}" data-vault-name="${escapeHTML(vault.name)}" data-r2-key="${escapeHTML(vault.r2_object_key)}">Manage Org</button>` : ''}
                ${vault.permission_level === 'manage' ? `<button class="delete-vault-btn danger-button" data-vault-id="${vault.id}">Delete</button>` : ''}
            </div>
        `;
        vaultsListDiv.appendChild(vaultItem);
    });

    vaultsListDiv.querySelectorAll('.load-vault-btn').forEach(button => {
        button.addEventListener('click', (event) => {
            const vaultId = parseInt(event.target.dataset.vaultId);
            const vaultName = event.target.dataset.vaultName;
            const vaultDescription = event.target.dataset.vaultDescription;
            const r2Key = event.target.dataset.r2Key;
            onVaultLoad(vaultId, vaultName, vaultDescription, r2Key);
        });
    });

    vaultsListDiv.querySelectorAll('.manage-vault-btn').forEach(button => {
        button.addEventListener('click', (event) => {
            const vaultId = parseInt(event.target.dataset.vaultId);
            const vaultName = event.target.dataset.vaultName;
            onVaultManage(vaultId, vaultName);
        });
    });

    vaultsListDiv.querySelectorAll('.delete-vault-btn').forEach(button => {
        button.addEventListener('click', (event) => {
            const vaultId = parseInt(event.target.dataset.vaultId);
            if (confirm('Are you sure you want to delete this vault and ALL its entries? This action cannot be undone.')) {
                onVaultDelete(vaultId);
            }
        });
    });
}

export function populateEntriesList(entries, onEntryCopyUsername, onEntryShowCopyPassword, onEntryDelete) {
    entriesListDiv.innerHTML = '';
    if (entries.length === 0) {
        entriesListDiv.innerHTML = '<p class="no-entries-message">No entries found in this vault. Add one above!</p>';
        return;
    }

    entries.forEach(entry => {
        const entryItem = document.createElement('div');
        entryItem.className = 'entry-item';
        entryItem.innerHTML = `
            <h4>${escapeHTML(entry.name)}</h4>
            <p><strong>Username:</strong> <span id="username-${entry.id}">${escapeHTML(entry.username)}</span></p>
            <p><strong>Password:</strong> <span id="password-${entry.id}" class="masked">**********</span></p>
            ${entry.url ? `<p><strong>URL:</strong> <a href="${escapeHTML(entry.url)}" target="_blank">${escapeHTML(entry.url)}</a></p>` : ''}
            ${entry.notes ? `<p><strong>Notes:</strong> ${escapeHTML(entry.notes)}</p>` : ''}
            <div class="actions">
                <button class="copy-username-btn" data-id="${entry.id}" data-clipboard-text="${escapeHTML(entry.username)}">Copy Username</button>
                <button class="show-copy-password-btn" data-id="${entry.id}" data-password="${escapeHTML(entry.password)}">Show/Copy Password</button>
                <button class="delete-entry-btn danger-button" data-id="${entry.id}">Delete Entry</button>
            </div>
        `;
        entriesListDiv.appendChild(entryItem);
    });

    entriesListDiv.querySelectorAll('.copy-username-btn').forEach(button => {
        button.addEventListener('click', (event) => {
            onEntryCopyUsername(event.target);
        });
    });

    entriesListDiv.querySelectorAll('.show-copy-password-btn').forEach(button => {
        button.addEventListener('click', (event) => {
            onEntryShowCopyPassword(event.target);
        });
    });

    entriesListDiv.querySelectorAll('.delete-entry-btn').forEach(button => {
        button.addEventListener('click', (event) => {
            const entryId = event.target.dataset.id;
            if (confirm('Are you sure you want to delete this entry? Remember to click "Save Vault Data" to make it permanent.')) {
                onEntryDelete(entryId);
            }
        });
    });
}

export function showLoading(text = "Loading...") {
    loadingText.textContent = text;
    showElement(loadingOverlay);
}

export function hideLoading() {
    hideElement(loadingOverlay);
}

export function showModal(modalElement) {
    modalElement.classList.remove('hidden');
    // Close modal on click outside content or on close button
    modalElement.querySelector('.close-modal').onclick = () => hideElement(modalElement);
    modalElement.onclick = (event) => {
        if (event.target === modalElement) {
            hideElement(modalElement);
        }
    };
}

export function hideModal(modalElement) {
    modalElement.classList.add('hidden');
}

export function populateOrganizationDropdown(organizations, currentOrgId = null) {
    selectOrganizationDropdown.innerHTML = '';
    organizations.forEach(org => {
        const option = document.createElement('option');
        option.value = org.id;
        option.textContent = org.name;
        if (currentOrgId && org.id === currentOrgId) {
            option.selected = true;
        }
        selectOrganizationDropdown.appendChild(option);
    });
    // Add "New Organization" option
    const newOrgOption = document.createElement('option');
    newOrgOption.value = 'new';
    newOrgOption.textContent = 'Create New Organization...';
    selectOrganizationDropdown.appendChild(newOrgOption);
}


// Helper for escaping HTML to prevent XSS when displaying user-controlled content
function escapeHTML(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}