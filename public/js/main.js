// public/js/main.js

import {
    registerUser, loginUser, createVault, getVaults,
    saveEncryptedVaultData, loadEncryptedVaultData, deleteVault,
    getUserEncryptionSalt, updateMasterPassword,
    createOrganization, getOrganizations, addMemberToOrganization,
    getOrgMembers, updateMemberRole, removeMember, deleteOrganization,
    deleteAccount
} from './api.js';
import { deriveKey, encryptData, decryptData } from './crypto.js';
import {
    storeSession, getSessionToken, getUserInfo, clearSession,
    isLoggedIn, startInactivityTimer, stopInactivityTimer
} from './session.js';
import {
    showElement, hideElement, showMessage, clearForm,
    authSection, appSection, loginTab, registerTab,
    loginForm, registerForm, authMessage,
    loginEmailInput, loginMasterPasswordInput,
    registerEmailInput, registerMasterPasswordInput, registerConfirmMasterPasswordInput, passwordStrengthText,
    userEmailDisplay, logoutButton,
    newVaultNameInput, newVaultDescriptionInput, createVaultButton, vaultsListDiv, vaultMessage,
    vaultDetailsSection, currentVaultName, currentVaultDescription, deleteCurrentVaultButton, loadAnotherVaultButton,
    addEntryForm, entryNameInput, entryUsernameInput, entryPasswordInput, generatePasswordButton, entryUrlInput, entryNotesInput,
    entriesListDiv, saveVaultDataButton, entryMessage, searchEntriesInput, searchButton, clearSearchButton,
    changeMasterPasswordButton, changeMasterPasswordModal, changeMasterPasswordForm,
    oldMasterPasswordInput, newMasterPasswordInput, confirmNewMasterPasswordInput, newPasswordStrengthText, changePasswordMessage,
    exportVaultDataButton,
    populateVaultsList, populateEntriesList, populateOrganizationDropdown,
    populateOrganisationsScreen, showLoading, hideLoading, showModal, hideModal,
    newVaultOwnerTypeSelect, organizationSelectionDiv, selectOrganizationDropdown, createOrganizationButton,
    createOrganizationModal, orgNameInput, orgDescriptionInput, submitCreateOrgButton, orgModalMessage,
    addOrgMemberModal, addMemberOrgName, memberEmailInput, memberRoleSelect, submitAddMemberButton, addMemberModalMessage,
    deleteAccountButton, deleteAccountModal, deleteAccountForm, deleteAccountPasswordInput, deleteAccountMessage,
    vaultsScreen, organisationsScreen, createOrgFromScreenButton, orgScreenMessage,
    vaultsSection, loadingText
} from './ui.js';
import { checkPasswordStrength, generateSalt, generateRandomPassword, searchVaultEntries, copyToClipboard, uint8ArrayToHexString } from './utils.js';
import { DEFAULT_MASTER_PASSWORD_CHANGE_LOADING_MESSAGE } from './constants.js';


let currentEncryptionKey = null;
let currentVaultData = null; // Array of password entries
let currentVaultMetadata = null; // { id, name, description, r2_object_key, ... }
let organizations = []; // Stores user's organizations
let loadedVaults = []; // Cache of all vaults returned by last getVaults() call


// --- Initialization ---
document.addEventListener('DOMContentLoaded', init);

function init() {
    setupEventListeners();
    if (isLoggedIn()) {
        showApp();
    } else {
        showAuth();
    }
}

// --- UI State Management ---
function showAuth() {
    hideElement(appSection);
    showElement(authSection);
    clearSession(); // Ensure session is clear when showing auth
    clearForm(loginForm);
    clearForm(registerForm);
    authMessage.textContent = '';
    // Activate login tab by default
    document.querySelector('.tab-button[data-tab="login"]').classList.add('active');
    document.querySelector('.tab-button[data-tab="register"]').classList.remove('active');
    showElement(loginTab);
    hideElement(registerTab);
}

async function showApp() {
    hideElement(authSection);
    showElement(appSection);
    userEmailDisplay.textContent = getUserInfo()?.email || 'User';
    startInactivityTimer();
    await loadVaults();
}

function showVaultDetails() {
    hideElement(vaultsSection);
    showElement(vaultDetailsSection);
    currentVaultName.textContent = currentVaultMetadata.name;
    currentVaultDescription.textContent = currentVaultMetadata.description || 'No description provided.';
    populateEntriesList(currentVaultData, handleCopyUsername, handleShowCopyPassword, handleEntryDelete);
}

function hideVaultDetails() {
    hideElement(vaultDetailsSection);
    showElement(vaultsSection);
    clearForm(addEntryForm);
    entryMessage.textContent = '';
    searchEntriesInput.value = '';
    currentVaultData = null;
    currentVaultMetadata = null;
}

// --- Event Listeners ---
function setupEventListeners() {
    // Auth Tabs
    document.querySelector('.tab-buttons').addEventListener('click', (event) => {
        if (event.target.classList.contains('tab-button')) {
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            if (event.target.dataset.tab === 'login') {
                showElement(loginTab);
                hideElement(registerTab);
            } else {
                showElement(registerTab);
                hideElement(loginTab);
            }
            authMessage.textContent = ''; // Clear message on tab switch
        }
    });

    // Forms
    loginForm.addEventListener('submit', handleLogin);
    registerForm.addEventListener('submit', handleRegister);
    logoutButton.addEventListener('click', showAuth);
    createVaultButton.addEventListener('click', handleCreateVault);
    addEntryForm.addEventListener('submit', handleAddEntry);
    saveVaultDataButton.addEventListener('click', handleSaveVaultData);
    deleteCurrentVaultButton.addEventListener('click', handleDeleteCurrentVault);
    loadAnotherVaultButton.addEventListener('click', handleLoadAnotherVault);
    searchButton.addEventListener('click', handleSearchEntries);
    clearSearchButton.addEventListener('click', handleClearSearch);
    generatePasswordButton.addEventListener('click', handleGeneratePassword);

    // Password Strength Indicator
    registerMasterPasswordInput.addEventListener('input', (event) => {
        const { strength, color } = checkPasswordStrength(event.target.value);
        passwordStrengthText.textContent = strength;
        passwordStrengthText.style.color = color;
    });
    newMasterPasswordInput.addEventListener('input', (event) => {
        const { strength, color } = checkPasswordStrength(event.target.value);
        newPasswordStrengthText.textContent = strength;
        newPasswordStrengthText.style.color = color;
    });

    // Change Master Password Modal
    changeMasterPasswordButton.addEventListener('click', () => showModal(changeMasterPasswordModal));
    changeMasterPasswordForm.addEventListener('submit', handleChangeMasterPassword);
    document.querySelectorAll('.close-modal').forEach(btn => btn.addEventListener('click', (event) => {
        hideModal(event.target.closest('.modal'));
        clearForm(changeMasterPasswordForm);
        changePasswordMessage.textContent = '';
    }));

    // Export Data
    exportVaultDataButton.addEventListener('click', handleExportAllVaultData);

    // Delete Account
    deleteAccountButton.addEventListener('click', () => showModal(deleteAccountModal));
    deleteAccountForm.addEventListener('submit', handleDeleteAccount);

    // App tab navigation
    document.querySelector('.app-tab-buttons').addEventListener('click', (event) => {
        if (event.target.classList.contains('app-tab-button')) {
            switchAppTab(event.target.dataset.appTab);
        }
    });

    // Create org from the Organisations tab
    createOrgFromScreenButton.addEventListener('click', () => showModal(createOrganizationModal));

    // Organization Handling
    newVaultOwnerTypeSelect.addEventListener('change', handleOwnerTypeChange);
    createOrganizationButton.addEventListener('click', () => showModal(createOrganizationModal));
    submitCreateOrgButton.addEventListener('click', handleCreateOrganization);
    submitAddMemberButton.addEventListener('click', handleAddMemberToOrganization);

    // Close Modals by clicking outside
    createOrganizationModal.addEventListener('click', (event) => {
        if (event.target === createOrganizationModal) hideModal(createOrganizationModal);
    });
    addOrgMemberModal.addEventListener('click', (event) => {
        if (event.target === addOrgMemberModal) hideModal(addOrgMemberModal);
    });
}

// --- Auth Handlers ---
async function handleRegister(event) {
    event.preventDefault();
    const email = registerEmailInput.value;
    const masterPassword = registerMasterPasswordInput.value;
    const confirmPassword = registerConfirmMasterPasswordInput.value;

    if (masterPassword !== confirmPassword) {
        showMessage(authMessage, 'Master passwords do not match.', 'error');
        return;
    }
    if (checkPasswordStrength(masterPassword).score < 3) {
        showMessage(authMessage, 'Please choose a stronger Master Password.', 'error');
        return;
    }

    showLoading("Registering user...");
    try {
        const encryptionSalt = generateSalt(); // Client-side salt for key derivation
        const saltHex = await registerUser(email, masterPassword, uint8ArrayToHexString(encryptionSalt)); // Server gets password hash, not actual password
        showMessage(authMessage, 'Registration successful! Please login.', 'success');
        clearForm(registerForm);
        // Switch to login tab
        document.querySelector('.tab-button[data-tab="login"]').click();
    } catch (error) {
        console.error('Registration failed:', error);
        showMessage(authMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const email = loginEmailInput.value;
    const masterPassword = loginMasterPasswordInput.value;

    showLoading("Logging in...");
    try {
        const { userId, email: userEmail, encryptionSalt, token } = await loginUser(email, masterPassword);

        const encryptionKey = await deriveKey(masterPassword, encryptionSalt);
        currentEncryptionKey = encryptionKey; // Store the derived key globally for the session

        storeSession(token, { userId, email: userEmail, encryptionSalt });
        showMessage(authMessage, 'Login successful!', 'success');
        clearForm(loginForm);
        await showApp();
    } catch (error) {
        console.error('Login failed:', error);
        showMessage(authMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleChangeMasterPassword(event) {
    event.preventDefault();
    const oldPassword = oldMasterPasswordInput.value;
    const newPassword = newMasterPasswordInput.value;
    const confirmNewPassword = confirmNewMasterPasswordInput.value;
    const userInfo = getUserInfo();

    if (newPassword !== confirmNewPassword) {
        showMessage(changePasswordMessage, 'New passwords do not match.', 'error');
        return;
    }
    if (checkPasswordStrength(newPassword).score < 3) {
        showMessage(changePasswordMessage, 'Please choose a stronger New Master Password.', 'error');
        return;
    }
    if (!userInfo?.userId) {
        showMessage(changePasswordMessage, 'User information not found. Please re-login.', 'error');
        return;
    }

    showLoading(DEFAULT_MASTER_PASSWORD_CHANGE_LOADING_MESSAGE);
    try {
        // Step 1: Re-derive old key from existing salt
        const oldEncryptionKey = await deriveKey(oldPassword, userInfo.encryptionSalt);

        // Step 2: Download all vault data, decrypt with old key
        const allVaultsMetadata = await getVaults();
        const reEncryptedVaults = [];

        for (const vault of allVaultsMetadata) {
            const rawEncryptedData = await loadEncryptedVaultData(vault.id);

            let decryptedData = [];
            if (rawEncryptedData && rawEncryptedData.encryptedData) {
                decryptedData = await decryptData(rawEncryptedData.encryptedData, oldEncryptionKey);
            }
            reEncryptedVaults.push({ vaultId: vault.id, data: decryptedData });
        }

        // Step 3: Generate new client-side encryption salt
        const newEncryptionSalt = generateSalt();
        const newEncryptionKey = await deriveKey(newPassword, uint8ArrayToHexString(newEncryptionSalt));

        // Step 4: Re-encrypt all vault data with new key and new salt, upload
        for (const reEncryptedVault of reEncryptedVaults) {
            const encryptedPayload = await encryptData(reEncryptedVault.data, newEncryptionKey);
            await saveEncryptedVaultData(reEncryptedVault.vaultId, encryptedPayload);
        }

        // Step 5: Update user's master password hash and encryption salt on the server
        await updateMasterPassword(userInfo.userId, oldPassword, newPassword, uint8ArrayToHexString(newEncryptionSalt));

        // Update local session with new salt
        const updatedUserInfo = { ...userInfo, encryptionSalt: uint8ArrayToHexString(newEncryptionSalt) };
        storeSession(getSessionToken(), updatedUserInfo); // Re-store session with updated info

        currentEncryptionKey = newEncryptionKey; // Update global encryption key

        showMessage(changePasswordMessage, 'Master Password changed successfully!', 'success');
        clearForm(changeMasterPasswordForm);
        hideModal(changeMasterPasswordModal);
        alert('Master Password successfully changed! Your data has been re-encrypted.');

    } catch (error) {
        console.error('Master Password change failed:', error);
        showMessage(changePasswordMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleDeleteAccount(event) {
    event.preventDefault();
    const masterPassword = deleteAccountPasswordInput.value;
    const userInfo = getUserInfo();

    if (!userInfo?.userId) {
        showMessage(deleteAccountMessage, 'User information not found. Please re-login.', 'error');
        return;
    }

    showLoading("Deleting account and all vault data...");
    try {
        await deleteAccount(userInfo.userId, masterPassword);
        hideModal(deleteAccountModal);
        clearSession();
        alert('Your account has been permanently deleted.');
        window.location.reload();
    } catch (error) {
        console.error('Account deletion failed:', error);
        showMessage(deleteAccountMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleExportAllVaultData() {
    const userInfo = getUserInfo();
    if (!userInfo || !currentEncryptionKey) {
        alert("Not logged in or encryption key not available.");
        return;
    }

    showLoading("Exporting vault data...");
    try {
        const allVaultsMetadata = await getVaults();
        const exportData = {
            metadata: [],
            encryptedVaults: {}
        };

        for (const vault of allVaultsMetadata) {
            const rawEncryptedData = await loadEncryptedVaultData(vault.id);
            if (rawEncryptedData && rawEncryptedData.encryptedData) {
                exportData.encryptedVaults[vault.id] = rawEncryptedData.encryptedData;
            } else {
                exportData.encryptedVaults[vault.id] = null; // Mark as empty or no data
            }
            exportData.metadata.push({
                id: vault.id,
                name: vault.name,
                description: vault.description,
                owner_id: vault.owner_id,
                owner_type: vault.owner_type,
                r2_object_key: vault.r2_object_key,
                current_key_version: vault.current_key_version
                // Do NOT export server-side generated salts or sensitive server data
            });
        }

        // This export data is still ENCRYPTED at the vault level.
        // The user would need their Master Password to decrypt it if re-imported.
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `secure_password_manager_export_${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        alert('All encrypted vault data exported successfully. Keep this file and your Master Password safe!');

    } catch (error) {
        console.error('Error exporting vault data:', error);
        alert(`Failed to export data: ${error.message}`);
    } finally {
        hideLoading();
    }
}


// --- Vault Management ---
export async function loadVaults() {
    showLoading("Loading vaults...");
    try {
        organizations = await getOrganizations();
        populateOrganizationDropdown(organizations);

        const vaults = await getVaults();
        loadedVaults = vaults;
        populateVaultsList(vaults, organizations, handleLoadVault, handleDeleteVault);
        hideVaultDetails();
        showMessage(vaultMessage, `Loaded ${vaults.length} vaults.`, 'success');
    } catch (error) {
        console.error('Error loading vaults:', error);
        showMessage(vaultMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleCreateVault(event) {
    event.preventDefault();
    const vaultName = newVaultNameInput.value.trim();
    const vaultDescription = newVaultDescriptionInput.value.trim();
    const ownerType = newVaultOwnerTypeSelect.value;
    let ownerId = '';
    let initialPermissionLevel = 'manage';

    if (!vaultName) {
        showMessage(vaultMessage, 'Vault name cannot be empty.', 'error');
        return;
    }

    const userInfo = getUserInfo();
    if (!userInfo?.userId) {
        showMessage(vaultMessage, 'User not logged in.', 'error');
        return;
    }

    if (ownerType === 'user') {
        ownerId = `user_${userInfo.userId}`;
    } else if (ownerType === 'organization') {
        const selectedOrgId = selectOrganizationDropdown.value;
        if (!selectedOrgId || selectedOrgId === 'new') {
            showMessage(vaultMessage, 'Please select an organization or create a new one.', 'error');
            return;
        }
        ownerId = `org_${selectedOrgId}`; // Add prefix
    } else {
        showMessage(vaultMessage, 'Invalid owner type selected.', 'error');
        return;
    }

    showLoading("Creating vault...");
    try {
        const newVault = await createVault(vaultName, vaultDescription, ownerId, ownerType, 'auto-generated', initialPermissionLevel);
        currentVaultData = [];
        const encryptedInitialData = await encryptData(currentVaultData, currentEncryptionKey);
        await saveEncryptedVaultData(newVault.id, encryptedInitialData);

        showMessage(vaultMessage, `Vault '${newVault.name}' created and initialized!`, 'success');
        clearForm(newVaultNameInput.closest('form'));
        newVaultDescriptionInput.value = '';
        newVaultOwnerTypeSelect.value = 'user';
        handleOwnerTypeChange();
        await loadVaults();
    } catch (error) {
        console.error('Error creating vault:', error);
        showMessage(vaultMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}


async function handleLoadVault(vaultId, vaultName, vaultDescription, r2ObjectKey) {
    showLoading(`Loading vault '${vaultName}'...`);
    try {
        const rawEncryptedData = await loadEncryptedVaultData(vaultId);

        if (rawEncryptedData && rawEncryptedData.encryptedData) {
            // Decrypt the data using the current session's encryption key
            currentVaultData = await decryptData(rawEncryptedData.encryptedData, currentEncryptionKey);
            currentVaultMetadata = {
                id: vaultId,
                name: vaultName,
                description: vaultDescription,
                r2_object_key: r2ObjectKey
            };
            showMessage(entryMessage, `Vault '${vaultName}' loaded.`, 'success');
            showVaultDetails();
        } else {
            // Vault is empty or no data yet
            currentVaultData = [];
            currentVaultMetadata = {
                id: vaultId,
                name: vaultName,
                description: vaultDescription,
                r2_object_key: r2ObjectKey
            };
            showMessage(entryMessage, `Vault '${vaultName}' loaded. It's empty, add some entries!`, 'info');
            showVaultDetails();
        }
    } catch (error) {
        console.error('Error loading or decrypting vault:', error);
        showMessage(entryMessage, error.message, 'error');
        // If decryption fails, force re-login as the key might be wrong
        if (error.message.includes('Master Password')) {
            alert("Failed to decrypt vault data. Your Master Password might be incorrect or data corrupted. Please log in again.");
            showAuth();
        }
    } finally {
        hideLoading();
    }
}

async function handleDeleteVault(vaultId) {
    showLoading("Deleting vault...");
    try {
        await deleteVault(vaultId);
        showMessage(vaultMessage, 'Vault deleted successfully!', 'success');
        await loadVaults(); // Reload the list of vaults
        // If the current loaded vault was deleted, clear its details
        if (currentVaultMetadata && currentVaultMetadata.id === vaultId) {
            hideVaultDetails();
            currentVaultMetadata = null;
            currentVaultData = null;
        }
    } catch (error) {
        console.error('Error deleting vault:', error);
        showMessage(vaultMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleDeleteCurrentVault() {
    if (!currentVaultMetadata) return;
    if (!confirm(`Are you sure you want to delete vault '${currentVaultMetadata.name}' and ALL its entries? This cannot be undone.`)) return;
    await handleDeleteVault(currentVaultMetadata.id);
}

function handleLoadAnotherVault() {
    hideVaultDetails();
    currentVaultData = null;
    currentVaultMetadata = null;
    entryMessage.textContent = '';
    searchEntriesInput.value = ''; // Clear search when changing vault
    clearForm(addEntryForm);
}

// --- Entry Management ---
async function handleAddEntry(event) {
    event.preventDefault();
    if (!currentVaultData) {
        showMessage(entryMessage, 'No vault loaded. Please load a vault first.', 'error');
        return;
    }

    const name = entryNameInput.value.trim();
    const username = entryUsernameInput.value.trim();
    const password = entryPasswordInput.value.trim();
    const url = entryUrlInput.value.trim();
    const notes = entryNotesInput.value.trim();

    if (!name || !username || !password) {
        showMessage(entryMessage, 'Entry name, username, and password are required.', 'error');
        return;
    }

    const newEntry = {
        id: crypto.randomUUID(), // Generate a unique ID for the entry
        name,
        username,
        password,
        url: url || undefined, // Store undefined if empty
        notes: notes || undefined
    };

    currentVaultData.push(newEntry);
    populateEntriesList(currentVaultData, handleCopyUsername, handleShowCopyPassword, handleEntryDelete);
    showMessage(entryMessage, 'Entry added to vault (remember to click "Save Vault Data"!)', 'info');
    clearForm(addEntryForm);
}

function handleEntryDelete(entryId) {
    if (!currentVaultData) return;

    currentVaultData = currentVaultData.filter(entry => entry.id !== entryId);
    populateEntriesList(currentVaultData, handleCopyUsername, handleShowCopyPassword, handleEntryDelete);
    showMessage(entryMessage, 'Entry removed from vault (remember to click "Save Vault Data"!)', 'info');
}

async function handleSaveVaultData() {
    if (!currentVaultMetadata || !currentVaultData || !currentEncryptionKey) {
        showMessage(entryMessage, 'No vault loaded or encryption key missing.', 'error');
        return;
    }

    showLoading("Saving vault data...");
    try {
        const encryptedPayload = await encryptData(currentVaultData, currentEncryptionKey);
        await saveEncryptedVaultData(currentVaultMetadata.id, encryptedPayload);
        showMessage(entryMessage, 'Vault data saved successfully!', 'success');
    } catch (error) {
        console.error('Error saving vault data:', error);
        showMessage(entryMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

function handleGeneratePassword() {
    entryPasswordInput.value = generateRandomPassword();
}

function handleCopyUsername(buttonElement) {
    const usernameText = buttonElement.dataset.clipboardText;
    copyToClipboard(usernameText, buttonElement);
}

function handleShowCopyPassword(buttonElement) {
    const password = buttonElement.dataset.password;
    const entryId = buttonElement.dataset.id;
    const passwordSpan = document.getElementById(`password-${entryId}`);

    passwordSpan.textContent = password;
    passwordSpan.classList.remove('masked');
    copyToClipboard(password, buttonElement);

    // Re-mask after a short delay
    setTimeout(() => {
        passwordSpan.textContent = '**********';
        passwordSpan.classList.add('masked');
    }, 2000); // Mask after 2 seconds
}

function handleSearchEntries() {
    if (!currentVaultData) return;
    const query = searchEntriesInput.value.trim();
    if (query) {
        const filteredEntries = searchVaultEntries(query, currentVaultData);
        populateEntriesList(filteredEntries, handleCopyUsername, handleShowCopyPassword, handleEntryDelete);
    } else {
        populateEntriesList(currentVaultData, handleCopyUsername, handleShowCopyPassword, handleEntryDelete);
    }
}

function handleClearSearch() {
    searchEntriesInput.value = '';
    if (currentVaultData) {
        populateEntriesList(currentVaultData, handleCopyUsername, handleShowCopyPassword, handleEntryDelete);
    }
}

// --- App Tab Navigation ---
function switchAppTab(tabName) {
    document.querySelectorAll('.app-tab-button').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.appTab === tabName);
    });
    if (tabName === 'vaults') {
        showElement(vaultsScreen);
        hideElement(organisationsScreen);
    } else if (tabName === 'organisations') {
        hideElement(vaultsScreen);
        showElement(organisationsScreen);
        loadOrganisationsScreen();
    }
}

async function loadOrganisationsScreen() {
    showLoading("Loading organisations...");
    orgScreenMessage.textContent = '';
    try {
        organizations = await getOrganizations();
        populateOrganizationDropdown(organizations);

        const orgsWithMembers = await Promise.all(
            organizations.map(async org => {
                const members = await getOrgMembers(org.id);
                return { org, members };
            })
        );

        const userInfo = getUserInfo();
        populateOrganisationsScreen(orgsWithMembers, userInfo.userId, {
            onAddMember: (org) => {
                addMemberOrgName.textContent = `Organisation: ${org.name}`;
                addOrgMemberModal.dataset.orgId = String(org.id);
                showModal(addOrgMemberModal);
            },
            onUpdateRole: handleUpdateMemberRole,
            onRemoveMember: handleRemoveMember,
            onDeleteOrg: handleDeleteOrganisation
        });
    } catch (error) {
        console.error('Error loading organisations screen:', error);
        showMessage(orgScreenMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleUpdateMemberRole(orgId, userId, role) {
    showLoading("Updating role...");
    try {
        await updateMemberRole(orgId, userId, role);
        await loadOrganisationsScreen();
    } catch (error) {
        console.error('Error updating role:', error);
        showMessage(orgScreenMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleRemoveMember(orgId, userId) {
    if (!confirm('Remove this member from the organisation?')) return;
    showLoading("Removing member...");
    try {
        await removeMember(orgId, userId);
        await loadOrganisationsScreen();
    } catch (error) {
        console.error('Error removing member:', error);
        showMessage(orgScreenMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleDeleteOrganisation(orgId, orgName) {
    if (!confirm(`Permanently delete organisation "${orgName}" and ALL its vaults? This cannot be undone.`)) return;
    showLoading("Deleting organisation...");
    try {
        await deleteOrganization(orgId);
        organizations = organizations.filter(o => o.id !== orgId);
        loadedVaults = loadedVaults.filter(v => v.owner_id !== `org_${orgId}`);
        populateOrganizationDropdown(organizations);
        await loadOrganisationsScreen();
        showMessage(orgScreenMessage, `Organisation "${orgName}" deleted.`, 'success');
    } catch (error) {
        console.error('Error deleting organisation:', error);
        showMessage(orgScreenMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

// --- Organization Handlers ---
async function handleOwnerTypeChange() {
    if (newVaultOwnerTypeSelect.value === 'organization') {
        showElement(organizationSelectionDiv);
        await loadOrganizationsForDropdown();
    } else {
        hideElement(organizationSelectionDiv);
        selectOrganizationDropdown.innerHTML = ''; // Clear options
    }
}

async function loadOrganizationsForDropdown() {
    showLoading("Loading organizations...");
    try {
        organizations = await getOrganizations();
        populateOrganizationDropdown(organizations);
    } catch (error) {
        console.error('Error loading organizations:', error);
        showMessage(vaultMessage, `Failed to load organizations: ${error.message}`, 'error');
    } finally {
        hideLoading();
    }
}

async function handleCreateOrganization() {
    const name = orgNameInput.value.trim();
    const description = orgDescriptionInput.value.trim();

    if (!name) {
        showMessage(orgModalMessage, 'Organization name cannot be empty.', 'error');
        return;
    }

    showLoading("Creating organization...");
    try {
        const newOrg = await createOrganization(name, description);
        showMessage(orgModalMessage, `Organization '${newOrg.name}' created!`, 'success');
        clearForm(orgNameInput.closest('form'));
        hideModal(createOrganizationModal);
        await loadOrganizationsForDropdown();
        if (!organisationsScreen.classList.contains('hidden')) {
            await loadOrganisationsScreen();
        }
    } catch (error) {
        console.error('Error creating organization:', error);
        showMessage(orgModalMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}

async function handleAddMemberToOrganization() {
    const orgId = addOrgMemberModal.dataset.orgId;
    const memberEmail = memberEmailInput.value.trim();
    const role = memberRoleSelect.value;

    if (!memberEmail) {
        showMessage(addMemberModalMessage, 'Member email cannot be empty.', 'error');
        return;
    }

    showLoading("Adding member...");
    try {
        await addMemberToOrganization(orgId, memberEmail, role);
        showMessage(addMemberModalMessage, `Member ${memberEmail} added as ${role}!`, 'success');
        clearForm(memberEmailInput.closest('form'));
        hideModal(addOrgMemberModal);
        if (!organisationsScreen.classList.contains('hidden')) {
            await loadOrganisationsScreen();
        }
    } catch (error) {
        console.error('Error adding member:', error);
        showMessage(addMemberModalMessage, error.message, 'error');
    } finally {
        hideLoading();
    }
}
