// public/js/drawer.js — right-side entry detail drawer.

import { cloneTemplate, escapeHTML } from './ui.js';
import { copyToClipboard } from './clipboard.js';

let lastFocus = null;
let onDeleteCallback = null;

function elements() {
    return {
        drawer: document.getElementById('entry-drawer'),
        scrim:  document.getElementById('entry-drawer-scrim')
    };
}

export function openEntryDrawer(entry, { onDelete } = {}) {
    const { drawer, scrim } = elements();
    if (!drawer) return;

    lastFocus = document.activeElement;
    onDeleteCallback = onDelete;

    drawer.innerHTML = '';
    drawer.appendChild(cloneTemplate('tpl-entry-drawer-body'));

    drawer.querySelector('[data-name]').textContent = entry.name ?? '';
    drawer.querySelector('[data-username]').textContent = entry.username ?? '';

    const passwordEl = drawer.querySelector('[data-password]');
    let revealed = false;
    const maskedDisplay = '•'.repeat(Math.min(entry.password?.length ?? 8, 14));
    passwordEl.textContent = maskedDisplay;

    const togglePwdBtn = drawer.querySelector('[data-toggle-password]');
    togglePwdBtn.addEventListener('click', () => {
        revealed = !revealed;
        passwordEl.textContent = revealed ? entry.password : maskedDisplay;
        togglePwdBtn.querySelector('.icon').textContent = revealed ? 'visibility_off' : 'visibility';
    });

    drawer.querySelector('[data-copy-username]').addEventListener('click', () => {
        copyToClipboard(entry.username);
    });
    drawer.querySelector('[data-copy-password]').addEventListener('click', () => {
        copyToClipboard(entry.password);
    });

    const urlSection = drawer.querySelector('[data-url-section]');
    if (entry.url) {
        urlSection.hidden = false;
        const a = urlSection.querySelector('[data-url]');
        a.href = entry.url;
        a.textContent = entry.url;
    }

    const notesSection = drawer.querySelector('[data-notes-section]');
    if (entry.notes) {
        notesSection.hidden = false;
        notesSection.querySelector('[data-notes]').textContent = entry.notes;
    }

    drawer.querySelector('[data-delete]').addEventListener('click', () => {
        if (onDeleteCallback) onDeleteCallback(entry);
    });
    drawer.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click', closeEntryDrawer));
    scrim.addEventListener('click', closeEntryDrawer, { once: true });
    document.addEventListener('keydown', onEsc);

    drawer.classList.add('is-open');
    drawer.setAttribute('aria-hidden', 'false');
    scrim.classList.add('is-open');

    requestAnimationFrame(() => {
        drawer.querySelector('[data-close]')?.focus();
    });
}

export function closeEntryDrawer() {
    const { drawer, scrim } = elements();
    if (!drawer) return;
    drawer.classList.remove('is-open');
    drawer.setAttribute('aria-hidden', 'true');
    scrim.classList.remove('is-open');
    document.removeEventListener('keydown', onEsc);
    if (lastFocus && typeof lastFocus.focus === 'function') {
        lastFocus.focus();
    }
}

function onEsc(e) {
    if (e.key === 'Escape') closeEntryDrawer();
}
