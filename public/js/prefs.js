// public/js/prefs.js — UI preference loading, saving, and live application.
// Preferences are stored server-side (synced across devices) and cached in
// localStorage so the initial paint can apply them without a round-trip.

import { getPreferences, updatePreferences } from './api.js';

export const CACHE_KEY = 'passflares.prefs';

export const ALLOWED = {
    theme:   ['light', 'dark', 'system'],
    density: ['compact', 'comfortable', 'spacious'],
    shape:   ['sharp', 'rounded', 'pill'],
    accent:  ['emerald', 'blue', 'purple', 'orange']
};

export const DEFAULT_PREFS = {
    theme:   'system',
    density: 'comfortable',
    shape:   'rounded',
    accent:  'emerald'
};

const LISTENERS = new Set();
let current = { ...DEFAULT_PREFS };
let saveTimer = null;

function isValid(field, value) {
    return ALLOWED[field]?.includes(value);
}

export function getPrefs() {
    return { ...current };
}

export function applyPrefs(prefs, { persistCache = true } = {}) {
    const html = document.documentElement;
    const next = {};
    for (const field of Object.keys(DEFAULT_PREFS)) {
        const value = prefs[field];
        if (isValid(field, value)) {
            next[field] = value;
            html.dataset[field] = value;
        } else {
            next[field] = current[field] ?? DEFAULT_PREFS[field];
            html.dataset[field] = next[field];
        }
    }
    current = next;
    if (persistCache) {
        // localStorage.setItem can throw on quota errors or in private-browsing
        // contexts; the in-memory copy is still applied so we swallow it.
        try { localStorage.setItem(CACHE_KEY, JSON.stringify(current)); } catch {}
    }
    // Theme toggle icon mirrors current theme
    updateThemeToggleIcon();
    // A misbehaving listener shouldn't stop later listeners from running.
    LISTENERS.forEach(fn => { try { fn(current); } catch {} });
    return current;
}

export function onPrefsChange(fn) {
    LISTENERS.add(fn);
    return () => LISTENERS.delete(fn);
}

function readCache() {
    try {
        const raw = localStorage.getItem(CACHE_KEY);
        if (!raw) return null;
        return JSON.parse(raw);
    } catch {
        // Corrupt JSON or unavailable storage — fall back to defaults.
        return null;
    }
}

// Read OS prefers-color-scheme; expose for tests.
export function resolvedTheme(theme = current.theme) {
    if (theme === 'light' || theme === 'dark') return theme;
    if (typeof window === 'undefined' || !window.matchMedia) return 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function updateThemeToggleIcon() {
    const icon = document.getElementById('theme-toggle-icon');
    if (!icon) return;
    const btn = document.getElementById('theme-toggle-btn');
    if (current.theme === 'system') {
        icon.textContent = 'brightness_auto';
        if (btn) btn.title = `Theme: system (${resolvedTheme()})`;
    } else {
        icon.textContent = resolvedTheme() === 'dark' ? 'dark_mode' : 'light_mode';
        if (btn) btn.title = `Theme: ${current.theme}`;
    }
}

/**
 * Load prefs: first apply localStorage cache (no flicker), then fetch from
 * server. If server has different values, re-apply.
 */
export async function loadPrefs({ fetchRemote = true } = {}) {
    const cached = readCache();
    if (cached) applyPrefs(cached, { persistCache: false });
    else applyPrefs(DEFAULT_PREFS, { persistCache: false });

    if (!fetchRemote) return current;

    try {
        const remote = await getPreferences();
        if (remote) {
            applyPrefs({
                theme: remote.theme,
                density: remote.density,
                shape: remote.shape,
                accent: remote.accent
            });
        }
    } catch (err) {
        // Network/auth errors fall back to cache; not fatal.
        console.warn('Failed to fetch remote preferences:', err);
    }
    return current;
}

/**
 * Update prefs locally + push to server (debounced).
 */
export function setPrefs(patch) {
    const merged = { ...current, ...patch };
    applyPrefs(merged);

    clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
        try {
            await updatePreferences(patch);
        } catch (err) {
            console.warn('Failed to save preferences:', err);
        }
    }, 350);
}

// Live-respond to OS theme changes when on `system` mode.
export function watchSystemTheme() {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = () => { if (current.theme === 'system') updateThemeToggleIcon(); };
    mq.addEventListener?.('change', handler);
}
