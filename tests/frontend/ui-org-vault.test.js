// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeAll } from 'vitest';

// ui.js captures DOM element references at module load time,
// so the DOM must exist before the dynamic import runs.
document.body.innerHTML = `
    <div id="vaults-list"></div>
    <div id="organisations-list"></div>
    <div id="entries-list"></div>
    <div id="loading-overlay" class="hidden"><p id="loading-text"></p></div>
    <select id="select-organization"></select>
    <div id="auth-section"></div><div id="app-section"></div>
    <div id="login-tab"></div><div id="register-tab"></div>
    <form id="login-form"></form><form id="register-form"></form>
    <p id="auth-message"></p>
    <input id="login-email"><input id="login-master-password">
    <input id="register-email"><input id="register-master-password">
    <input id="register-confirm-master-password">
    <span id="password-strength-text"></span>
    <span id="user-email-display"></span><button id="logout-button"></button>
    <div id="vaults-section"></div><div id="vaults-screen"></div>
    <div id="organisations-screen"></div>
    <button id="create-org-from-screen-button"></button>
    <p id="org-screen-message"></p>
    <input id="new-vault-name"><textarea id="new-vault-description"></textarea>
    <select id="new-vault-owner-type"></select>
    <div id="organization-selection"></div>
    <button id="create-organization-button"></button><button id="create-vault-button"></button>
    <p id="vault-message"></p>
    <div id="vault-details-section"></div>
    <h2 id="current-vault-name"></h2><p id="current-vault-description"></p>
    <button id="delete-current-vault-button"></button><button id="load-another-vault-button"></button>
    <form id="add-entry-form"></form>
    <input id="entry-name"><input id="entry-username"><input id="entry-password">
    <button id="generate-password-button"></button>
    <input id="entry-url"><textarea id="entry-notes"></textarea>
    <button id="save-vault-data-button"></button><p id="entry-message"></p>
    <input id="search-entries"><button id="search-button"></button><button id="clear-search-button"></button>
    <button id="change-master-password-button"></button>
    <div id="change-master-password-modal"></div><form id="change-master-password-form"></form>
    <input id="old-master-password"><input id="new-master-password">
    <span id="new-password-strength-text"></span><input id="confirm-new-master-password">
    <p id="change-password-message"></p><button id="export-vault-data-button"></button>
    <button id="delete-account-button"></button><div id="delete-account-modal"></div>
    <form id="delete-account-form"></form><input id="delete-account-password">
    <p id="delete-account-message"></p>
    <div id="create-organization-modal"></div>
    <input id="org-name-input"><textarea id="org-description-input"></textarea>
    <button id="submit-create-org"></button><p id="org-modal-message"></p>
    <div id="add-org-member-modal"></div><h3 id="add-member-org-name"></h3>
    <input id="member-email-input"><select id="member-role-select"></select>
    <button id="submit-add-member"></button><p id="add-member-modal-message"></p>
`;

// Use dynamic import so ui.js loads AFTER the DOM is set up above
let populateVaultsList, populateOrganisationsScreen;
beforeAll(async () => {
    const ui = await import('../../public/js/ui.js');
    populateVaultsList = ui.populateVaultsList;
    populateOrganisationsScreen = ui.populateOrganisationsScreen;
});

// --- populateVaultsList ---

describe('populateVaultsList', () => {
    const orgs = [{ id: 3, name: 'Acme Corp', description: null }];

    it('shows empty state when no vaults', () => {
        populateVaultsList([], orgs, vi.fn(), vi.fn());
        expect(document.getElementById('vaults-list').textContent).toContain('No vaults found');
    });

    it('renders a personal vault with Personal badge', () => {
        const vaults = [{ id: 1, name: 'Home Passwords', description: 'Personal stuff', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'k1' }];
        populateVaultsList(vaults, orgs, vi.fn(), vi.fn());
        const list = document.getElementById('vaults-list');
        expect(list.textContent).toContain('Personal');
        expect(list.textContent).toContain('Home Passwords');
        expect(list.textContent).toContain('Personal Vaults');
    });

    it('renders an org vault with org name badge instead of ID', () => {
        const vaults = [{ id: 2, name: 'Team Vault', description: '', owner_type: 'organization', owner_id: 'org_3', permission_level: 'write', r2_object_key: 'k2' }];
        populateVaultsList(vaults, orgs, vi.fn(), vi.fn());
        const list = document.getElementById('vaults-list');
        expect(list.textContent).toContain('Acme Corp');
        expect(list.textContent).not.toContain('org_3');
        expect(list.textContent).toContain('Organisation Vaults');
    });

    it('shows "Org #N" when org is not in the orgs array', () => {
        const vaults = [{ id: 3, name: 'Mystery Vault', description: '', owner_type: 'organization', owner_id: 'org_999', permission_level: 'read', r2_object_key: 'k3' }];
        populateVaultsList(vaults, orgs, vi.fn(), vi.fn());
        expect(document.getElementById('vaults-list').textContent).toContain('Org #999');
    });

    it('renders separate sections when both personal and org vaults exist', () => {
        const vaults = [
            { id: 1, name: 'Personal', description: '', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'k1' },
            { id: 2, name: 'Team', description: '', owner_type: 'organization', owner_id: 'org_3', permission_level: 'write', r2_object_key: 'k2' }
        ];
        populateVaultsList(vaults, orgs, vi.fn(), vi.fn());
        const list = document.getElementById('vaults-list');
        expect(list.textContent).toContain('Personal Vaults');
        expect(list.textContent).toContain('Organisation Vaults');
    });

    it('calls onVaultLoad with correct args when Load is clicked', () => {
        const onLoad = vi.fn();
        const vault = { id: 7, name: 'Clickable', description: 'desc', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'rkey' };
        populateVaultsList([vault], orgs, onLoad, vi.fn());
        document.querySelector('.load-vault-btn').click();
        expect(onLoad).toHaveBeenCalledWith(7, 'Clickable', 'desc', 'rkey');
    });

    it('calls onVaultDelete when Delete is clicked and confirmed', () => {
        const onDelete = vi.fn();
        vi.stubGlobal('confirm', () => true);
        const vault = { id: 8, name: 'Del', description: '', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'rk2' };
        populateVaultsList([vault], orgs, vi.fn(), onDelete);
        document.querySelector('.delete-vault-btn').click();
        expect(onDelete).toHaveBeenCalledWith(8);
        vi.unstubAllGlobals();
    });

    it('does not render Delete button for read-only vaults', () => {
        const vault = { id: 9, name: 'ReadOnly', description: '', owner_type: 'user', owner_id: 'user_1', permission_level: 'read', r2_object_key: 'rk3' };
        populateVaultsList([vault], orgs, vi.fn(), vi.fn());
        expect(document.querySelector('.delete-vault-btn')).toBeNull();
    });
});

// --- populateOrganisationsScreen ---

describe('populateOrganisationsScreen', () => {
    const callbacks = { onAddMember: vi.fn(), onUpdateRole: vi.fn(), onRemoveMember: vi.fn(), onDeleteOrg: vi.fn() };

    it('shows empty state when no orgs', () => {
        populateOrganisationsScreen([], 1, callbacks);
        expect(document.getElementById('organisations-list').textContent).toContain('No organisations yet');
    });

    it('renders an org card with Owner badge for super_admin', () => {
        const org = { id: 1, name: 'My Org', description: 'desc' };
        const members = [{ userId: 1, email: 'owner@example.com', role: 'super_admin' }];
        populateOrganisationsScreen([{ org, members }], 1, callbacks);
        const list = document.getElementById('organisations-list');
        expect(list.textContent).toContain('My Org');
        expect(list.textContent).toContain('Owner');
    });

    it('renders Admin badge when user role is admin', () => {
        const org = { id: 2, name: 'Admin Org', description: '' };
        const members = [
            { userId: 1, email: 'admin@example.com', role: 'admin' },
            { userId: 2, email: 'owner@example.com', role: 'super_admin' }
        ];
        populateOrganisationsScreen([{ org, members }], 1, callbacks);
        // The badge for the current user (userId=1, admin) should show Admin
        const badge = document.querySelector('.org-role-badge.role-admin');
        expect(badge).not.toBeNull();
    });

    it('shows Delete Organisation button only for super_admin', () => {
        const org = { id: 3, name: 'Owner Org', description: '' };
        const members = [{ userId: 1, email: 'me@example.com', role: 'super_admin' }];
        populateOrganisationsScreen([{ org, members }], 1, callbacks);
        expect(document.querySelector('.delete-org-btn')).not.toBeNull();
    });

    it('does not show Delete Organisation button for admin', () => {
        const org = { id: 4, name: 'Admin Only', description: '' };
        const members = [
            { userId: 1, email: 'admin@example.com', role: 'admin' },
            { userId: 2, email: 'owner@example.com', role: 'super_admin' }
        ];
        populateOrganisationsScreen([{ org, members }], 1, callbacks);
        expect(document.querySelector('.delete-org-btn')).toBeNull();
    });

    it('toggles management panel on Manage button click', () => {
        const org = { id: 5, name: 'Toggle Org', description: '' };
        const members = [{ userId: 1, email: 'me@example.com', role: 'super_admin' }];
        populateOrganisationsScreen([{ org, members }], 1, callbacks);
        const panel = document.querySelector('.org-management-panel');
        expect(panel.classList.contains('hidden')).toBe(true);
        document.querySelector('.toggle-manage-btn').click();
        expect(panel.classList.contains('hidden')).toBe(false);
    });
});
