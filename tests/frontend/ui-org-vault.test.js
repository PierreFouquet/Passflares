// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from 'vitest';

// We need <template>s on the document because the new renderers use cloneTemplate().
function setupDOM() {
    document.body.innerHTML = `
        <div id="page-root"></div>

        <template id="tpl-vault-row">
            <a class="list-row" href="#" data-vault-row>
                <span class="list-row__icon"><span class="icon">lock</span></span>
                <div class="list-row__body">
                    <span class="list-row__title" data-name></span>
                    <span class="list-row__meta">
                        <span class="chip" data-owner-chip></span>
                        <span class="chip" data-perm-chip></span>
                        <span data-description></span>
                    </span>
                </div>
                <span class="list-row__actions">
                    <button type="button" class="icon-btn" data-vault-delete title="Delete vault" hidden>
                        <span class="icon">delete</span>
                    </button>
                    <span class="icon" aria-hidden="true">arrow_forward</span>
                </span>
            </a>
        </template>

        <template id="tpl-page-organisations">
            <div class="page-header"><h1>Organisations</h1></div>
            <div id="organisations-list-area"></div>
        </template>

        <template id="tpl-page-vaults">
            <div class="page-header"><h1>Vaults</h1></div>
            <div id="vault-detail-area" class="hidden"></div>
            <div id="vaults-list-area"></div>
        </template>
    `;
}

// localStorage stub
beforeEach(() => {
    setupDOM();
    localStorage.setItem('userInfo', JSON.stringify({ userId: 1, email: 'me@example.com' }));
});

// Helpers to import the renderers fresh per test
async function importVaults() {
    return await import('../../public/js/pages/vaults.js');
}
async function importOrgs() {
    return await import('../../public/js/pages/orgs.js');
}

// --- Vaults list renderer ---

describe('renderVaultList (new sectioned dense rows)', () => {
    const orgs = [{ id: 3, name: 'Acme Corp', description: null }];

    it('shows empty state when no vaults', async () => {
        const { renderVaultList } = await importVaults();
        const container = document.createElement('div');
        renderVaultList(container, [], orgs);
        expect(container.textContent).toContain('No vaults yet');
    });

    it('renders a Personal section for user-owned vaults', async () => {
        const { renderVaultList } = await importVaults();
        const container = document.createElement('div');
        renderVaultList(container, [
            { id: 1, name: 'Home', description: 'd', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'k1' }
        ], orgs);
        expect(container.textContent).toContain('Personal');
        expect(container.textContent).toContain('Home');
    });

    it('renders separate per-org sections with the org name', async () => {
        const { renderVaultList } = await importVaults();
        const container = document.createElement('div');
        renderVaultList(container, [
            { id: 2, name: 'Team', description: '', owner_type: 'organization', owner_id: 'org_3', permission_level: 'write', r2_object_key: 'k2' }
        ], orgs);
        expect(container.textContent).toContain('Acme Corp');
        expect(container.textContent).not.toContain('org_3');
    });

    it('falls back to "Org #N" when the org is unknown', async () => {
        const { renderVaultList } = await importVaults();
        const container = document.createElement('div');
        renderVaultList(container, [
            { id: 3, name: 'Mystery', description: '', owner_type: 'organization', owner_id: 'org_999', permission_level: 'read', r2_object_key: 'k3' }
        ], orgs);
        expect(container.textContent).toContain('Org #999');
    });

    it('renders Personal and Org sections together when both present', async () => {
        const { renderVaultList } = await importVaults();
        const container = document.createElement('div');
        renderVaultList(container, [
            { id: 1, name: 'P', description: '', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'k1' },
            { id: 2, name: 'T', description: '', owner_type: 'organization', owner_id: 'org_3', permission_level: 'write', r2_object_key: 'k2' }
        ], orgs);
        const headers = container.querySelectorAll('.list-section__header');
        expect(headers.length).toBe(2);
        expect(container.textContent).toContain('Personal');
        expect(container.textContent).toContain('Acme Corp');
    });

    it('shows the delete icon-button only for manage permission', async () => {
        const { renderVaultList } = await importVaults();
        const container = document.createElement('div');
        renderVaultList(container, [
            { id: 1, name: 'M', description: '', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'k1' },
            { id: 2, name: 'R', description: '', owner_type: 'user', owner_id: 'user_1', permission_level: 'read',   r2_object_key: 'k2' }
        ], orgs);
        const deleteBtns = Array.from(container.querySelectorAll('[data-vault-delete]'));
        // Two rows in template, but only one is unhidden
        const visible = deleteBtns.filter(b => !b.hidden);
        expect(visible.length).toBe(1);
    });

    it('renders the section count chip', async () => {
        const { renderVaultList } = await importVaults();
        const container = document.createElement('div');
        renderVaultList(container, [
            { id: 1, name: 'A', description: '', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'k1' },
            { id: 2, name: 'B', description: '', owner_type: 'user', owner_id: 'user_1', permission_level: 'manage', r2_object_key: 'k2' }
        ], orgs);
        expect(container.textContent).toMatch(/2 vaults/);
    });
});

// --- Orgs list renderer ---

describe('renderOrgCard / renderOrgList', () => {
    it('shows empty state when no orgs', async () => {
        const { renderOrgList } = await importOrgs();
        const container = document.createElement('div');
        renderOrgList(container, []);
        expect(container.textContent).toContain('No organisations yet');
    });

    it('renders an Owner chip when current user is super_admin', async () => {
        const { renderOrgCard } = await importOrgs();
        const org = { id: 1, name: 'My Org', description: 'desc' };
        const members = [{ userId: 1, email: 'owner@example.com', role: 'super_admin' }];
        const card = renderOrgCard(org, members, 1);
        expect(card.textContent).toContain('My Org');
        expect(card.textContent).toContain('Owner');
    });

    it('renders an Admin chip when current user is admin', async () => {
        const { renderOrgCard } = await importOrgs();
        const org = { id: 2, name: 'Admin Org', description: '' };
        const members = [
            { userId: 1, email: 'a@b.com', role: 'admin' },
            { userId: 2, email: 'owner@b.com', role: 'super_admin' }
        ];
        const card = renderOrgCard(org, members, 1);
        // The header chip reflects the *current user's* role
        expect(card.querySelector('.org-card__header .chip').textContent).toBe('Admin');
    });

    it('renders Delete-organisation button only for super_admin', async () => {
        const { renderOrgCard } = await importOrgs();
        const org = { id: 3, name: 'Owner Org', description: '' };
        const members = [{ userId: 1, email: 'me@b.com', role: 'super_admin' }];
        const card = renderOrgCard(org, members, 1);
        expect(card.querySelector('[data-delete-org]')).not.toBeNull();
    });

    it('hides Delete-organisation for admin', async () => {
        const { renderOrgCard } = await importOrgs();
        const org = { id: 4, name: 'Admin Only', description: '' };
        const members = [
            { userId: 1, email: 'a@b.com', role: 'admin' },
            { userId: 2, email: 'owner@b.com', role: 'super_admin' }
        ];
        const card = renderOrgCard(org, members, 1);
        expect(card.querySelector('[data-delete-org]')).toBeNull();
    });

    it('toggles management panel on click', async () => {
        const { renderOrgCard } = await importOrgs();
        const org = { id: 5, name: 'Toggle', description: '' };
        const members = [{ userId: 1, email: 'me@b.com', role: 'super_admin' }];
        const card = renderOrgCard(org, members, 1);
        const panel = card.querySelector('[data-panel]');
        expect(panel.classList.contains('hidden')).toBe(true);
        card.querySelector('[data-toggle-panel]').click();
        expect(panel.classList.contains('hidden')).toBe(false);
    });

    it('shows role <select> only for super_admin and not for self', async () => {
        const { renderOrgCard } = await importOrgs();
        const org = { id: 6, name: 'Org', description: '' };
        const members = [
            { userId: 1, email: 'me@b.com',    role: 'super_admin' },
            { userId: 2, email: 'other@b.com', role: 'member' }
        ];
        const card = renderOrgCard(org, members, 1);
        const selects = card.querySelectorAll('select');
        expect(selects.length).toBe(1); // only on the OTHER member
    });
});
