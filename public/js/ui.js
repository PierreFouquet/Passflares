// public/js/ui.js — shared DOM helpers used across pages.

export function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}

// Loading overlay
const loadingOverlay = () => document.getElementById('loading-overlay');
const loadingText = () => document.getElementById('loading-text');

export function showLoading(text = 'Loading…') {
    const overlay = loadingOverlay();
    if (!overlay) return;
    loadingText().textContent = text;
    overlay.classList.remove('hidden');
}

export function hideLoading() {
    const overlay = loadingOverlay();
    if (!overlay) return;
    overlay.classList.add('hidden');
}

// Populate a <select> with the user's organisations. Used by the vault creator.
export function populateOrganizationDropdown(selectEl, organizations, currentOrgId = null) {
    if (!selectEl) return;
    selectEl.innerHTML = '';
    if (organizations.length === 0) {
        const empty = document.createElement('option');
        empty.value = '';
        empty.textContent = 'No organisations — create one first';
        empty.disabled = true;
        empty.selected = true;
        selectEl.appendChild(empty);
        return;
    }
    organizations.forEach(org => {
        const option = document.createElement('option');
        option.value = String(org.id);
        option.textContent = org.name;
        if (currentOrgId && org.id === currentOrgId) option.selected = true;
        selectEl.appendChild(option);
    });
}

// Clone a <template id="…"> into a DocumentFragment.
export function cloneTemplate(id) {
    const tpl = document.getElementById(id);
    if (!tpl) throw new Error(`Template #${id} not found`);
    return tpl.content.cloneNode(true);
}

// Resolve the org name for a vault.owner_id like 'org_3' from a list of orgs.
export function resolveOrgName(ownerId, organizations) {
    if (!ownerId || !ownerId.startsWith('org_')) return 'Personal';
    const orgId = parseInt(ownerId.slice(4), 10);
    const org = organizations.find(o => o.id === orgId);
    return org ? org.name : `Org #${orgId}`;
}
