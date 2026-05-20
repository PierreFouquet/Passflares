// public/js/pages/dashboard.js — landing page after sign-in.
// Shows recent vaults + security overview (weak/reused passwords across decrypted vaults).

import { cloneTemplate, escapeHTML, resolveOrgName } from '../ui.js';
import { getVaults, getOrgs, getAllDecryptedEntries } from '../state.js';
import { getUserInfo } from '../session.js';
import { go } from '../router.js';
import { checkPasswordStrength } from '../utils.js';

const RECENT_LIMIT = 5;

export function renderDashboard({ mount }) {
    mount.appendChild(cloneTemplate('tpl-page-home'));

    const userInfo = getUserInfo();
    const slot = mount.querySelector('[data-user-name]');
    if (slot && userInfo?.email) slot.textContent = `, ${userInfo.email.split('@')[0]}`;

    // Action buttons
    mount.querySelector('[data-action="new-vault"]').addEventListener('click', () => go('vaults'));
    mount.querySelector('[data-action="open-generator"]').addEventListener('click', () => {
        // Set a hash that the vaults page picks up to focus the generator.
        location.hash = '#/vaults?generator=1';
    });

    renderSecurityTiles(mount.querySelector('[data-security-tiles]'));
    renderRecentVaults(mount.querySelector('[data-recent-vaults]'));
}

export function computeSecurityOverview(decryptedEntries) {
    const total = decryptedEntries.length;
    const pwSet = new Map();
    let weak = 0;
    let reused = 0;
    let oldStub = 0; // We don't have an updatedAt on entries; placeholder
    for (const { entry } of decryptedEntries) {
        if (!entry.password) continue;
        const s = checkPasswordStrength(entry.password);
        if (s.score < 3) weak += 1;
        pwSet.set(entry.password, (pwSet.get(entry.password) ?? 0) + 1);
    }
    for (const count of pwSet.values()) {
        if (count > 1) reused += count;
    }
    return { total, weak, reused, oldStub };
}

function renderSecurityTiles(container) {
    if (!container) return;
    const decrypted = getAllDecryptedEntries();
    const summary = computeSecurityOverview(decrypted);

    container.innerHTML = '';

    const isEmpty = decrypted.length === 0;
    const tiles = [
        {
            cls: 'tile--info',  icon: 'shield', label: 'Tracked entries',
            value: summary.total, sub: isEmpty ? 'Open a vault to populate' : 'Across all open vaults'
        },
        {
            cls: summary.weak > 0 ? 'tile--risk' : 'tile--good', icon: summary.weak > 0 ? 'warning' : 'check_circle',
            label: 'Weak passwords', value: summary.weak,
            sub: summary.weak > 0 ? 'Consider strengthening these' : 'No weak passwords detected'
        },
        {
            cls: summary.reused > 0 ? 'tile--warn' : 'tile--good', icon: summary.reused > 0 ? 'refresh' : 'check_circle',
            label: 'Reused passwords', value: summary.reused,
            sub: summary.reused > 0 ? 'Used across multiple entries' : 'All passwords are unique'
        },
        {
            cls: 'tile--good', icon: 'lock',
            label: 'Vaults', value: getVaults().length,
            sub: getVaults().filter(v => v.owner_type === 'organization').length + ' organisation vaults'
        }
    ];

    tiles.forEach(t => {
        const el = document.createElement('div');
        el.className = `tile ${t.cls}`;
        el.innerHTML = `
            <span class="tile__icon"><span class="icon">${t.icon}</span></span>
            <span class="tile__label">${escapeHTML(t.label)}</span>
            <span class="tile__value">${escapeHTML(String(t.value))}</span>
            <span class="tile__sub">${escapeHTML(t.sub)}</span>
        `;
        container.appendChild(el);
    });
}

function renderRecentVaults(container) {
    if (!container) return;
    container.innerHTML = '';
    const orgs = getOrgs();
    const vaults = getVaults().slice(0, RECENT_LIMIT);
    if (vaults.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <span class="icon">lock</span>
                <h3>No vaults yet</h3>
                <p>Create your first vault to start saving passwords.</p>
                <button type="button" class="btn btn--filled" data-action="new-vault">
                    <span class="icon">add</span>New vault
                </button>
            </div>
        `;
        container.querySelector('[data-action="new-vault"]').addEventListener('click', () => go('vaults'));
        return;
    }

    vaults.forEach(v => {
        const row = document.createElement('a');
        row.className = 'list-row';
        row.href = `#/vaults`;
        const ownerText = v.owner_type === 'organization' ? resolveOrgName(v.owner_id, orgs) : 'Personal';
        row.innerHTML = `
            <span class="list-row__icon"><span class="icon">lock</span></span>
            <div class="list-row__body">
                <span class="list-row__title">${escapeHTML(v.name)}</span>
                <span class="list-row__meta">
                    <span class="chip ${v.owner_type === 'organization' ? 'chip--primary' : 'chip--neutral'}">${escapeHTML(ownerText)}</span>
                    <span class="chip">${escapeHTML(v.permission_level ?? 'read')}</span>
                </span>
            </div>
            <span class="list-row__actions">
                <span class="icon" aria-hidden="true">arrow_forward</span>
            </span>
        `;
        container.appendChild(row);
    });
}
