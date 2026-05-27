// public/js/pages/orgs.js — organisations management.

import {
    createOrganization, getOrganizations, getOrgMembers,
    addMemberToOrganization, updateMemberRole, removeMember, deleteOrganization
} from '../api.js';
import { cloneTemplate, escapeHTML, showLoading, hideLoading } from '../ui.js';
import { snack } from '../snackbar.js';
import { openDialog, confirmDialog } from '../dialog.js';
import { setOrgs, getOrgs } from '../state.js';
import { getUserInfo } from '../session.js';

const ROLE_LABEL = { member: 'Member', admin: 'Admin', super_admin: 'Owner' };
const ROLE_CHIP_CLASS = { member: 'chip--neutral', admin: 'chip--info', super_admin: 'chip--purple' };

export async function renderOrgsPage({ mount }) {
    mount.appendChild(cloneTemplate('tpl-page-organisations'));
    mount.querySelector('[data-action="new-org"]').addEventListener('click', openCreateOrgDialog);
    await loadAndRender(mount);
}

async function loadAndRender(mount) {
    showLoading('Loading organisations…');
    try {
        const orgs = await getOrganizations();
        setOrgs(orgs);
        const data = await Promise.all(orgs.map(async (org) => ({
            org, members: await getOrgMembers(org.id)
        })));
        renderOrgList(mount.querySelector('#organisations-list-area'), data);
    } catch (err) {
        console.error('Loading organisations failed:', err);
        snack.error(err.message ?? 'Failed to load organisations.');
    } finally {
        hideLoading();
    }
}

export function renderOrgList(container, data) {
    container.innerHTML = '';
    if (data.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <span class="icon">groups</span>
                <h3>No organisations yet</h3>
                <p>Create an organisation to share vaults with your team.</p>
            </div>
        `;
        return;
    }
    const currentUserId = getUserInfo()?.userId;
    data.forEach(({ org, members }) => {
        container.appendChild(renderOrgCard(org, members, currentUserId));
    });
}

export function renderOrgCard(org, members, currentUserId) {
    const myMembership = members.find(m => m.userId === currentUserId);
    const myRole = myMembership?.role ?? 'member';
    const isSuper = myRole === 'super_admin';
    const isAdmin = myRole === 'admin' || isSuper;

    const card = document.createElement('article');
    card.className = 'org-card';
    card.dataset.orgId = String(org.id);
    card.innerHTML = `
        <header class="org-card__header">
            <h3 class="org-card__title">${escapeHTML(org.name)}</h3>
            <span class="chip ${ROLE_CHIP_CLASS[myRole]}">${escapeHTML(ROLE_LABEL[myRole])}</span>
        </header>
        <p class="org-card__description">${escapeHTML(org.description || 'No description.')}</p>
        <div class="org-card__actions">
            <button type="button" class="btn btn--tonal" data-toggle-panel>
                <span class="icon">groups</span>Manage members
            </button>
        </div>
        <div class="org-card__panel hidden" data-panel></div>
    `;

    const panel = card.querySelector('[data-panel]');
    card.querySelector('[data-toggle-panel]').addEventListener('click', () => panel.classList.toggle('hidden'));

    panel.innerHTML = `
        <h4 class="text-label mb-8px">Members</h4>
        <div data-members></div>
        <div class="row-end mt-3">
            ${isAdmin ? `<button type="button" class="btn btn--tonal" data-add-member><span class="icon">person_add</span>Add member</button>` : ''}
            ${isSuper ? `<button type="button" class="btn btn--danger-text" data-delete-org><span class="icon">delete</span>Delete organisation</button>` : ''}
        </div>
    `;

    const membersEl = panel.querySelector('[data-members]');
    members.forEach(m => membersEl.appendChild(renderMemberRow(m, currentUserId, isSuper, isAdmin, org.id)));

    panel.querySelector('[data-add-member]')?.addEventListener('click', () => openAddMemberDialog(org));
    panel.querySelector('[data-delete-org]')?.addEventListener('click', async () => {
        const ok = await confirmDialog({
            title: `Delete "${org.name}"?`,
            message: 'This permanently deletes the organisation and ALL its vaults. This cannot be undone.',
            confirmLabel: 'Delete organisation',
            variant: 'danger'
        });
        if (ok) {
            try {
                showLoading('Deleting organisation…');
                await deleteOrganization(org.id);
                snack.success(`Organisation "${org.name}" deleted.`);
                await loadAndRender(document.getElementById('page-root'));
            } catch (err) {
                snack.error(err.message ?? 'Failed to delete organisation.');
            } finally {
                hideLoading();
            }
        }
    });

    return card;
}

function renderMemberRow(member, currentUserId, isSuper, isAdmin, orgId) {
    const row = document.createElement('div');
    row.className = 'org-member-row';
    const isSelf = member.userId === currentUserId;

    row.innerHTML = `
        <span class="org-member-row__email">${escapeHTML(member.email)}${isSelf ? ' <em>(you)</em>' : ''}</span>
        <div class="org-member-row__actions">
            ${isSuper && !isSelf
                ? `<select aria-label="Role">
                      <option value="member"      ${member.role === 'member'      ? 'selected' : ''}>Member</option>
                      <option value="admin"       ${member.role === 'admin'       ? 'selected' : ''}>Admin</option>
                      <option value="super_admin" ${member.role === 'super_admin' ? 'selected' : ''}>Owner</option>
                   </select>
                   <button type="button" class="btn btn--text btn--sm" data-apply-role>Apply</button>`
                : `<span class="chip ${ROLE_CHIP_CLASS[member.role]}">${ROLE_LABEL[member.role]}</span>`}
            ${isAdmin && !isSelf
                ? `<button type="button" class="icon-btn icon-btn--sm icon-btn--danger" data-remove-member title="Remove">
                      <span class="icon">delete</span>
                   </button>`
                : ''}
        </div>
    `;

    row.querySelector('[data-apply-role]')?.addEventListener('click', async () => {
        const newRole = row.querySelector('select').value;
        try {
            showLoading('Updating role…');
            await updateMemberRole(orgId, member.userId, newRole);
            snack.success(`Updated ${member.email} → ${ROLE_LABEL[newRole]}`);
            await loadAndRender(document.getElementById('page-root'));
        } catch (err) {
            snack.error(err.message ?? 'Failed to update role.');
        } finally {
            hideLoading();
        }
    });

    row.querySelector('[data-remove-member]')?.addEventListener('click', async () => {
        const ok = await confirmDialog({
            title: 'Remove this member?',
            message: `Remove ${member.email} from this organisation?`,
            confirmLabel: 'Remove',
            variant: 'danger'
        });
        if (ok) {
            try {
                showLoading('Removing member…');
                await removeMember(orgId, member.userId);
                snack.success(`Removed ${member.email}.`);
                await loadAndRender(document.getElementById('page-root'));
            } catch (err) {
                snack.error(err.message ?? 'Failed to remove member.');
            } finally {
                hideLoading();
            }
        }
    });

    return row;
}

function openCreateOrgDialog() {
    const body = document.createElement('div');
    body.innerHTML = `
        <div class="field">
            <input type="text" id="dialog-org-name" placeholder=" " required>
            <label for="dialog-org-name">Organisation name</label>
        </div>
        <div class="field">
            <textarea id="dialog-org-description" placeholder=" "></textarea>
            <label for="dialog-org-description">Description (optional)</label>
        </div>
    `;
    openDialog({
        title: 'New organisation',
        body,
        actions: [
            { label: 'Cancel', variant: 'text' },
            {
                label: 'Create',
                variant: 'filled',
                onClick: async ({ close }) => {
                    const name = body.querySelector('#dialog-org-name').value.trim();
                    const description = body.querySelector('#dialog-org-description').value.trim();
                    if (!name) { snack.error('Name is required.'); return; }
                    try {
                        showLoading('Creating organisation…');
                        const newOrg = await createOrganization(name, description);
                        snack.success(`Organisation "${newOrg.name}" created.`);
                        close();
                        await loadAndRender(document.getElementById('page-root'));
                    } catch (err) {
                        snack.error(err.message ?? 'Failed to create organisation.');
                    } finally {
                        hideLoading();
                    }
                },
                closeOnClick: false
            }
        ]
    });
}

function openAddMemberDialog(org) {
    const body = document.createElement('div');
    body.innerHTML = `
        <p>Add a member to <strong>${escapeHTML(org.name)}</strong>.</p>
        <div class="field">
            <input type="email" id="dialog-member-email" placeholder=" " required>
            <label for="dialog-member-email">Email</label>
        </div>
        <div class="row mt-2">
            <label for="dialog-member-role" class="text-muted">Role</label>
            <select id="dialog-member-role">
                <option value="member">Member</option>
                <option value="admin">Admin</option>
            </select>
        </div>
    `;
    openDialog({
        title: 'Add member',
        body,
        actions: [
            { label: 'Cancel', variant: 'text' },
            {
                label: 'Add member',
                variant: 'filled',
                onClick: async ({ close }) => {
                    const email = body.querySelector('#dialog-member-email').value.trim();
                    const role  = body.querySelector('#dialog-member-role').value;
                    if (!email) { snack.error('Email is required.'); return; }
                    try {
                        showLoading('Adding member…');
                        await addMemberToOrganization(org.id, email, role);
                        snack.success(`Added ${email} as ${ROLE_LABEL[role]}.`);
                        close();
                        await loadAndRender(document.getElementById('page-root'));
                    } catch (err) {
                        snack.error(err.message ?? 'Failed to add member.');
                    } finally {
                        hideLoading();
                    }
                },
                closeOnClick: false
            }
        ]
    });
}
