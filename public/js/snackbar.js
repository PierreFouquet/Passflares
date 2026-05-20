// public/js/snackbar.js — toast notifications.
// Replaces inline .message elements throughout the app.

import { escapeHTML } from './ui.js';

const ICONS = {
    success: 'check_circle',
    error: 'error',
    warning: 'warning',
    info: 'info'
};

const DEFAULT_DURATIONS = {
    success: 3500,
    info:    3500,
    warning: 5000,
    error:   6000
};

function host() {
    return document.getElementById('snackbar-host');
}

export function showSnack({ message, type = 'info', duration } = {}) {
    if (!message) return null;
    const root = host();
    if (!root) return null;
    const lifetime = duration ?? DEFAULT_DURATIONS[type] ?? 3500;
    const el = document.createElement('div');
    el.className = `snackbar snackbar--${type}`;
    el.setAttribute('role', type === 'error' ? 'alert' : 'status');
    el.innerHTML = `
        <span class="icon snackbar__icon" aria-hidden="true">${ICONS[type] ?? ICONS.info}</span>
        <div class="snackbar__body">${escapeHTML(message)}</div>
        <button type="button" class="icon-btn icon-btn--sm snackbar__close" aria-label="Dismiss">
            <span class="icon">close</span>
        </button>
    `;
    root.appendChild(el);

    const dismiss = () => {
        if (!el.isConnected) return;
        el.classList.add('is-closing');
        setTimeout(() => el.remove(), 180);
    };

    el.querySelector('.snackbar__close').addEventListener('click', dismiss);

    if (lifetime > 0) {
        setTimeout(dismiss, lifetime);
    }

    return { dismiss, el };
}

export const snack = {
    success: (message, opts) => showSnack({ message, type: 'success', ...opts }),
    error:   (message, opts) => showSnack({ message, type: 'error',   ...opts }),
    warning: (message, opts) => showSnack({ message, type: 'warning', ...opts }),
    info:    (message, opts) => showSnack({ message, type: 'info',    ...opts })
};
