// public/js/pages/vaults.js — vaults list + vault detail + entry management.

import {
    createVault, getVaults as apiGetVaults, getOrganizations,
    saveEncryptedVaultData, deleteVault as apiDeleteVault
} from '../api.js';
import { encryptData } from '../crypto.js';
import { cloneTemplate, escapeHTML, resolveOrgName, showLoading, hideLoading, populateOrganizationDropdown } from '../ui.js';
import {
    getVaults, setVaults, getOrgs, setOrgs, hasPrivateKey, getVaultKey,
    setDecryptedVault, getDecryptedVault, setCurrentVault
} from '../state.js';
import {
    decryptVaultContents, provisionVaultKey, rescueLegacyOrgVault,
    VaultKeyUnavailableError
} from '../vault-keys.js';
import { getUserInfo } from '../session.js';
import { snack } from '../snackbar.js';
import { confirmDialog } from '../dialog.js';
import { openEntryDrawer, closeEntryDrawer } from '../drawer.js';
import { generateRandomPassword } from '../utils.js';
import { copyToClipboard } from '../clipboard.js';

let creatorOpen = false;

export async function renderVaultsPage({ mount }) {
    mount.appendChild(cloneTemplate('tpl-page-vaults'));

    const newBtn = mount.querySelector('[data-action="new-vault"]');
    newBtn.addEventListener('click', toggleCreator);

    await loadVaultsAndRender(mount);
}

export async function loadVaultsAndRender(root) {
    showLoading('Loading vaults…');
    try {
        const orgs = await getOrganizations();
        setOrgs(orgs);
        const vaults = await apiGetVaults();
        setVaults(vaults);
        renderVaultList(root.querySelector('#vaults-list-area'), vaults, orgs);
    } catch (err) {
        console.error('Failed to load vaults:', err);
        snack.error(err.message ?? 'Failed to load vaults.');
    } finally {
        hideLoading();
    }
}

function toggleCreator() {
    const root = document.getElementById('page-root');
    if (creatorOpen) {
        root.querySelector('.composer')?.remove();
        creatorOpen = false;
        return;
    }
    creatorOpen = true;
    const frag = cloneTemplate('tpl-vault-creator');
    const container = root.querySelector('#vaults-list-area');
    container.insertAdjacentElement('beforebegin', frag.firstElementChild);
    const composer = root.querySelector('.composer');
    const orgs = getOrgs();
    const select = composer.querySelector('#select-organization');
    populateOrganizationDropdown(select, orgs);

    composer.querySelectorAll('input[name="new-vault-owner-type"]').forEach(r => {
        r.addEventListener('change', () => {
            const isOrg = r.checked && r.value === 'organization';
            composer.querySelector('#organization-selection').classList.toggle('hidden', !isOrg);
        });
    });

    composer.querySelector('[data-cancel-create]').addEventListener('click', toggleCreator);
    composer.querySelector('#create-vault-button').addEventListener('click', () => handleCreateVault(composer));
}

async function handleCreateVault(composer) {
    const name = composer.querySelector('#new-vault-name').value.trim();
    const description = composer.querySelector('#new-vault-description').value.trim();
    const ownerType = composer.querySelector('input[name="new-vault-owner-type"]:checked').value;

    if (!name) { snack.error('Vault name cannot be empty.'); return; }

    const userInfo = getUserInfo() ?? {};
    let ownerId = `user_${userInfo.userId}`;
    if (ownerType === 'organization') {
        const selected = composer.querySelector('#select-organization').value;
        if (!selected) { snack.error('Please select an organisation.'); return; }
        ownerId = `org_${selected}`;
    }

    if (!hasPrivateKey()) { snack.error('Vault unlocked session lost — please sign in again.'); return; }

    showLoading('Creating vault…');
    let newVault = null;
    try {
        newVault = await createVault(name, description, ownerId, ownerType, 'manage');

        // The vault key is wrapped against the vault's id, so it can only be
        // provisioned once the row exists. If this fails the vault would be
        // unopenable, so remove it rather than leave a broken shell behind — it
        // is still empty, so nothing is lost.
        const { skipped } = await provisionVaultKey(newVault, {
            selfUserId: userInfo.userId,
            selfPublicKey: userInfo.publicKey
        });

        const vaultKey = getVaultKey(newVault.id);
        await saveEncryptedVaultData(newVault.id, await encryptData([], vaultKey), 'v2');

        snack.success(`Vault "${newVault.name}" created.`);
        if (skipped.length > 0) {
            snack.warning(
                `${skipped.length} member(s) can't access it yet — they need to sign in once to set up their keys.`
            );
        }
        creatorOpen = false;
        composer.remove();
        await loadVaultsAndRender(document.getElementById('page-root'));
    } catch (err) {
        console.error('Create vault failed:', err);
        if (newVault?.id) {
            try { await apiDeleteVault(newVault.id); } catch { /* best effort */ }
        }
        snack.error(err.message ?? 'Failed to create vault.');
    } finally {
        hideLoading();
    }
}

function renderVaultList(container, vaults, orgs) {
    container.innerHTML = '';
    if (vaults.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <span class="icon">lock</span>
                <h3>No vaults yet</h3>
                <p>Create your first vault to start saving passwords.</p>
            </div>
        `;
        return;
    }

    const personal = vaults.filter(v => v.owner_type === 'user');
    const byOrg = new Map();
    for (const v of vaults.filter(v => v.owner_type === 'organization')) {
        const key = v.owner_id;
        if (!byOrg.has(key)) byOrg.set(key, []);
        byOrg.get(key).push(v);
    }

    if (personal.length > 0) {
        container.appendChild(renderSection('Personal', personal, orgs, 'person'));
    }
    for (const [ownerId, list] of byOrg) {
        const name = resolveOrgName(ownerId, orgs);
        container.appendChild(renderSection(name, list, orgs, 'groups'));
    }
}

function renderSection(title, vaults, orgs, iconName) {
    const wrap = document.createElement('section');
    wrap.className = 'list-section';
    wrap.innerHTML = `
        <header class="list-section__header">
            <span><span class="icon icon--sm icon--inline">${escapeHTML(iconName)}</span>${escapeHTML(title)}</span>
            <span class="list-section__count">${vaults.length} vault${vaults.length === 1 ? '' : 's'}</span>
        </header>
    `;
    const list = document.createElement('div');
    list.className = 'list';
    vaults.forEach(v => list.appendChild(renderVaultRow(v, orgs)));
    wrap.appendChild(list);
    return wrap;
}

function renderVaultRow(vault, orgs) {
    const frag = cloneTemplate('tpl-vault-row');
    const row = frag.querySelector('[data-vault-row]');
    row.querySelector('[data-name]').textContent = vault.name;

    const ownerChip = row.querySelector('[data-owner-chip]');
    if (vault.owner_type === 'organization') {
        ownerChip.classList.add('chip--primary');
        ownerChip.textContent = resolveOrgName(vault.owner_id, orgs);
    } else {
        ownerChip.classList.add('chip--neutral');
        ownerChip.textContent = 'Personal';
    }

    const permChip = row.querySelector('[data-perm-chip]');
    permChip.textContent = vault.permission_level ?? 'read';
    if (vault.permission_level === 'manage') permChip.classList.add('chip--purple');
    else if (vault.permission_level === 'write') permChip.classList.add('chip--info');
    else permChip.classList.add('chip--neutral');

    const desc = row.querySelector('[data-description]');
    desc.textContent = vault.description ? `· ${vault.description}` : '';

    const deleteBtn = row.querySelector('[data-vault-delete]');
    if (vault.permission_level === 'manage') {
        deleteBtn.hidden = false;
        deleteBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            const ok = await confirmDialog({
                title: `Delete "${vault.name}"?`,
                message: 'This permanently deletes the vault and ALL its entries. This cannot be undone.',
                confirmLabel: 'Delete vault',
                variant: 'danger'
            });
            if (ok) doDeleteVault(vault.id);
        });
    }

    row.addEventListener('click', async (e) => {
        if (e.target.closest('[data-vault-delete]')) return;
        e.preventDefault();
        await openVaultDetail(vault, orgs);
    });

    return row;
}

async function doDeleteVault(vaultId) {
    showLoading('Deleting vault…');
    try {
        await apiDeleteVault(vaultId);
        snack.success('Vault deleted.');
        await loadVaultsAndRender(document.getElementById('page-root'));
    } catch (err) {
        snack.error(err.message ?? 'Failed to delete vault.');
    } finally {
        hideLoading();
    }
}

async function openVaultDetail(vault, orgs) {
    showLoading(`Opening "${vault.name}"…`);
    try {
        let payload = getDecryptedVault(vault.id);
        if (!payload) {
            const { entries, usedLegacyKey } = await decryptVaultContents(vault);

            // An organisation vault that only opened with the legacy key is one
            // that predates the key hierarchy: it was encrypted under its
            // creator's personal password, which is exactly why no other member
            // could ever read it (#69). We are that creator — re-key it now and
            // wrap the new key for everyone.
            if (usedLegacyKey && vault.owner_type === 'organization') {
                hideLoading();
                showLoading(`Repairing shared access for "${vault.name}"…`);
                try {
                    const { granted, skipped } = await rescueLegacyOrgVault(vault, entries);
                    vault.current_key_version = 'v2';
                    vault.has_key_share = true;
                    snack.success(`"${vault.name}" is now readable by ${granted} member(s).`);
                    if (skipped.length > 0) {
                        snack.warning(
                            `${skipped.length} member(s) still need to sign in once before they can be granted access.`
                        );
                    }
                } catch (rescueError) {
                    // The vault is still readable by us via the legacy key, so
                    // this is a degraded state, not a failure to open.
                    console.error('Org vault rescue failed:', rescueError);
                    snack.warning('Could not repair shared access for this vault. Other members still cannot open it.');
                }
            }

            payload = { metadata: vault, entries };
            setDecryptedVault(vault.id, payload);
        }
        setCurrentVault(vault.id);

        const root = document.getElementById('page-root');
        const detail = root.querySelector('#vault-detail-area');
        const listArea = root.querySelector('#vaults-list-area');
        detail.classList.remove('hidden');
        listArea.classList.add('hidden');
        renderVaultDetail(detail, payload, orgs);
    } catch (err) {
        console.error('Open vault failed:', err);
        // VaultKeyUnavailableError already carries an accurate explanation. The
        // old code told a keyless org member their password was wrong, which was
        // both false and unactionable.
        snack.error(err instanceof VaultKeyUnavailableError
            ? err.message
            : (err.message ?? 'Failed to open vault.'));
    } finally {
        hideLoading();
    }
}

function renderVaultDetail(container, payload, orgs) {
    const { metadata, entries } = payload;
    container.innerHTML = '';
    const ownerLabel = metadata.owner_type === 'organization' ? resolveOrgName(metadata.owner_id, orgs) : 'Personal';

    container.innerHTML = `
        <button type="button" class="btn btn--text" data-back-btn>
            <span class="icon">arrow_back</span>Back to vaults
        </button>
        <div class="card mt-3">
            <header class="card__header">
                <div>
                    <h2 class="card__title">${escapeHTML(metadata.name)}</h2>
                    <p class="card__description">${escapeHTML(metadata.description || 'No description.')}</p>
                </div>
                <div class="row">
                    <span class="chip ${metadata.owner_type === 'organization' ? 'chip--primary' : 'chip--neutral'}">${escapeHTML(ownerLabel)}</span>
                    <span class="chip">${escapeHTML(metadata.permission_level ?? 'read')}</span>
                </div>
            </header>
        </div>

        <section class="composer">
            <h3>Add a new entry</h3>
            <div class="stack">
                <div class="field">
                    <input type="text" id="entry-name" placeholder=" " required>
                    <label for="entry-name">Entry name</label>
                </div>
                <div class="row row-wrap">
                    <div class="field field--grow">
                        <input type="text" id="entry-username" placeholder=" " required>
                        <label for="entry-username">Username / email</label>
                    </div>
                    <div class="field field--grow password-field">
                        <input type="text" id="entry-password" placeholder=" " required>
                        <label for="entry-password">Password</label>
                        <button type="button" class="icon-btn icon-btn--sm" data-toggle-generator aria-label="Open generator">
                            <span class="icon">key</span>
                        </button>
                    </div>
                </div>
                <div class="generator-panel hidden" data-generator>
                    <div class="generator-panel__output">
                        <span class="generator-panel__output-text" data-gen-output>Click Generate to start</span>
                        <button type="button" class="icon-btn icon-btn--sm" data-gen-copy title="Copy"><span class="icon">content_copy</span></button>
                        <button type="button" class="icon-btn icon-btn--sm" data-gen-use title="Use this"><span class="icon">check</span></button>
                    </div>
                    <div class="generator-panel__row">
                        <div class="generator-panel__length">
                            <span>Length:</span>
                            <input type="range" class="slider" min="8" max="64" value="20" data-gen-length>
                            <span data-gen-length-display>20</span>
                        </div>
                        <button type="button" class="btn btn--tonal btn--sm" data-gen-regen>
                            <span class="icon">refresh</span>Generate
                        </button>
                    </div>
                </div>
                <div class="field">
                    <input type="url" id="entry-url" placeholder=" ">
                    <label for="entry-url">URL (optional)</label>
                </div>
                <div class="field">
                    <textarea id="entry-notes" placeholder=" "></textarea>
                    <label for="entry-notes">Notes (optional)</label>
                </div>
                <div class="row-end">
                    <button type="button" class="btn btn--filled" id="add-entry-btn">
                        <span class="icon">add_circle</span>Add entry
                    </button>
                </div>
            </div>
        </section>

        <div class="row row-between mb-3">
            <h2>Entries (<span data-entries-count></span>)</h2>
            <div class="row">
                <button type="button" class="btn btn--filled" id="save-vault-btn">
                    <span class="icon">save</span>Save vault
                </button>
                ${metadata.permission_level === 'manage' ? `
                    <button type="button" class="btn btn--danger-text" data-delete-vault>
                        <span class="icon">delete</span>Delete vault
                    </button>` : ''}
            </div>
        </div>
        <div class="list" data-entries-list></div>
    `;

    container.querySelector('[data-back-btn]').addEventListener('click', backToList);

    // Generator wiring
    const genPanel = container.querySelector('[data-generator]');
    const lengthInput = genPanel.querySelector('[data-gen-length]');
    const lengthDisplay = genPanel.querySelector('[data-gen-length-display]');
    const outputEl = genPanel.querySelector('[data-gen-output]');
    let generated = '';
    const regen = () => {
        generated = generateRandomPassword(Number(lengthInput.value));
        outputEl.textContent = generated;
    };
    container.querySelector('[data-toggle-generator]').addEventListener('click', () => {
        genPanel.classList.toggle('hidden');
        if (!genPanel.classList.contains('hidden') && !generated) regen();
    });
    lengthInput.addEventListener('input', () => { lengthDisplay.textContent = lengthInput.value; regen(); });
    genPanel.querySelector('[data-gen-regen]').addEventListener('click', regen);
    genPanel.querySelector('[data-gen-copy]').addEventListener('click', () => copyToClipboard(generated));
    genPanel.querySelector('[data-gen-use]').addEventListener('click', () => {
        container.querySelector('#entry-password').value = generated;
        snack.success('Password inserted into entry.');
    });

    container.querySelector('#add-entry-btn').addEventListener('click', () => handleAddEntry(container, payload));
    container.querySelector('#save-vault-btn').addEventListener('click', () => handleSaveVault(container, payload));
    container.querySelector('[data-delete-vault]')?.addEventListener('click', async () => {
        const ok = await confirmDialog({
            title: `Delete "${metadata.name}"?`,
            message: 'This permanently deletes the vault and ALL its entries. This cannot be undone.',
            confirmLabel: 'Delete vault',
            variant: 'danger'
        });
        if (ok) {
            await doDeleteVault(metadata.id);
            backToList();
        }
    });

    renderEntries(container, payload);
}

function renderEntries(container, payload) {
    const list = container.querySelector('[data-entries-list]');
    const count = container.querySelector('[data-entries-count]');
    list.innerHTML = '';
    count.textContent = String(payload.entries.length);

    if (payload.entries.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <span class="icon">key</span>
                <h3>No entries yet</h3>
                <p>Add your first credential above to get started.</p>
            </div>
        `;
        return;
    }

    payload.entries.forEach(entry => {
        const frag = cloneTemplate('tpl-entry-row');
        const row = frag.querySelector('[data-entry-row]');
        row.querySelector('[data-name]').textContent = entry.name;
        row.querySelector('[data-username]').textContent = entry.username ?? '';
        row.querySelector('[data-url]').textContent = entry.url ? ` · ${entry.url}` : '';
        row.querySelector('[data-copy-username]').addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            copyToClipboard(entry.username, { successMessage: 'Username copied.' });
        });
        row.addEventListener('click', (e) => {
            if (e.target.closest('[data-copy-username]')) return;
            e.preventDefault();
            openEntryDrawer(entry, {
                onDelete: async () => {
                    const ok = await confirmDialog({
                        title: 'Delete entry?',
                        message: `Remove "${entry.name}" from this vault? Remember to save afterwards.`,
                        confirmLabel: 'Delete',
                        variant: 'danger'
                    });
                    if (!ok) return;
                    payload.entries = payload.entries.filter(e => e.id !== entry.id);
                    setDecryptedVault(payload.metadata.id, payload);
                    closeEntryDrawer();
                    renderEntries(container, payload);
                    snack.info('Entry removed. Click "Save vault" to persist.');
                }
            });
        });
        list.appendChild(row);
    });
}

function handleAddEntry(container, payload) {
    const name = container.querySelector('#entry-name').value.trim();
    const username = container.querySelector('#entry-username').value.trim();
    const password = container.querySelector('#entry-password').value.trim();
    const url = container.querySelector('#entry-url').value.trim();
    const notes = container.querySelector('#entry-notes').value.trim();

    if (!name || !username || !password) {
        snack.error('Name, username and password are required.');
        return;
    }
    const entry = {
        id: crypto.randomUUID(),
        name, username, password,
        url: url || undefined,
        notes: notes || undefined
    };
    payload.entries.push(entry);
    setDecryptedVault(payload.metadata.id, payload);
    renderEntries(container, payload);

    container.querySelector('#entry-name').value = '';
    container.querySelector('#entry-username').value = '';
    container.querySelector('#entry-password').value = '';
    container.querySelector('#entry-url').value = '';
    container.querySelector('#entry-notes').value = '';
    container.querySelector('[data-generator]').classList.add('hidden');

    snack.info('Entry added. Click "Save vault" to persist.');
}

async function handleSaveVault(container, payload) {
    const vaultKey = getVaultKey(payload.metadata.id);
    if (!vaultKey) { snack.error('Vault unlocked session lost — please sign in again.'); return; }
    showLoading('Encrypting and saving vault…');
    try {
        const encryptedPayload = await encryptData(payload.entries, vaultKey);
        // No keyVersion: an ordinary save writes in place at the vault's live
        // version. Staging is only for re-encryption under a *new* key.
        await saveEncryptedVaultData(payload.metadata.id, encryptedPayload);
        snack.success('Vault saved successfully.');
    } catch (err) {
        console.error('Save vault failed:', err);
        snack.error(err.message ?? 'Failed to save vault.');
    } finally {
        hideLoading();
    }
}

function backToList() {
    const root = document.getElementById('page-root');
    root.querySelector('#vault-detail-area').classList.add('hidden');
    root.querySelector('#vaults-list-area').classList.remove('hidden');
    closeEntryDrawer();
    setCurrentVault(null);
}

// Exported for tests
export { renderVaultList, renderSection, renderVaultRow };
