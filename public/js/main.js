// public/js/main.js — boot file. Wires the shell, router, and pages.

import { isLoggedIn, getUserInfo, clearSession, startInactivityTimer, stopInactivityTimer } from './session.js';
import { loadPrefs, watchSystemTheme, getPrefs, setPrefs } from './prefs.js';
import { snack } from './snackbar.js';
import { showLoading, hideLoading } from './ui.js';
import { registerRoute, registerFallback, setMountElement, start, go } from './router.js';
import { attachMenu } from './menu.js';
import { initAuthPage } from './pages/auth.js';
import { renderDashboard } from './pages/dashboard.js';
import { renderVaultsPage, loadVaultsAndRender } from './pages/vaults.js';
import { renderOrgsPage } from './pages/orgs.js';
import { renderSettingsPage } from './pages/settings.js';
import { attachShortcut as attachSearchShortcut, attachAppBarSearch, buildIndex, setOnSelect, open as openPalette, close as closePalette } from './search.js';
import { reset as resetState, getVaults, getAllDecryptedEntries, hasKey, setKey } from './state.js';
import { closeEntryDrawer } from './drawer.js';
import { getOrganizations } from './api.js';
import { setOrgs } from './state.js';

document.addEventListener('DOMContentLoaded', boot);

async function boot() {
    // Test seam (e2e only). The encryption key is a derived CryptoKey held
    // in memory, so it can't be persisted across reload. Tests that want to
    // exercise the signed-in path inject a placeholder by setting this
    // window flag in `page.addInitScript`. Production never sets it; grep
    // for `__PASSFLARES_E2E_FAKE_KEY` to find every test that depends on
    // it. See [tests/e2e/fixtures.ts] `gotoAndSeedLogin`.
    if (typeof window !== 'undefined' && window.__PASSFLARES_E2E_FAKE_KEY) {
        setKey(window.__PASSFLARES_E2E_FAKE_KEY);
    }

    // 1. Always apply cached prefs immediately (already done by the inline
    //    script in <head>, but we re-apply via the JS pipeline so listeners
    //    fire). Server fetch happens only when authenticated.
    await loadPrefs({ fetchRemote: isLoggedIn() });
    watchSystemTheme();

    if (isLoggedIn() && hasKey()) {
        await showApp();
    } else if (isLoggedIn()) {
        // Token persisted in localStorage, but the encryption key only lives
        // in memory and is gone after a page reload. The token alone is
        // useless for decryption, so send the user back to sign in.
        const cachedUser = getUserInfo();
        showAuth({
            prefillEmail: cachedUser?.email,
            notice: 'Your session was locked when the page reloaded. Sign in again to unlock your vaults.'
        });
    } else {
        showAuth();
    }
}

function showAuth({ prefillEmail, notice } = {}) {
    document.getElementById('auth-screen')?.classList.remove('hidden');
    document.getElementById('app-shell')?.classList.add('hidden');
    clearSession();
    resetState();
    stopInactivityTimer();
    initAuthPage({ onLogin: () => showApp(), prefillEmail, notice });
}

async function showApp() {
    document.getElementById('auth-screen')?.classList.add('hidden');
    document.getElementById('app-shell')?.classList.remove('hidden');
    startInactivityTimer();
    await loadPrefs({ fetchRemote: true });
    wireShell();
    await prefetchVaults();
    registerRoutes();
    setMountElement(document.getElementById('page-root'));
    await start({ defaultRoute: 'home' });
}

async function prefetchVaults() {
    // Quietly load vaults + orgs so the dashboard and palette have data.
    try {
        const orgs = await getOrganizations();
        setOrgs(orgs);
        // Vaults metadata loaded by the vaults page on first render; not blocking here.
    } catch (err) {
        console.warn('Failed to prefetch organisations:', err);
    }
}

function registerRoutes() {
    registerRoute('home',          ctx => renderDashboard(ctx));
    registerRoute('vaults',        ctx => renderVaultsPage(ctx));
    registerRoute('organisations', ctx => renderOrgsPage(ctx));
    registerRoute('settings',      ctx => renderSettingsPage(ctx));
    registerFallback(ctx => renderDashboard(ctx));
}

function wireShell() {
    // Inject brand SVG in app bar — parse via DOMParser instead of innerHTML
    // so even a same-origin SVG can't be executed as HTML if the file is
    // ever swapped. Mirrors the same pattern in pages/auth.js.
    fetch('img/logo.svg')
        .then(r => r.text())
        .then(svg => {
            const slot = document.querySelector('[data-logo-slot]');
            if (!slot) return;
            const doc = new DOMParser().parseFromString(svg, 'image/svg+xml');
            const node = doc.documentElement;
            if (node && node.nodeName.toLowerCase() === 'svg') {
                slot.replaceChildren(node);
            }
        })
        .catch(() => {});

    // Theme toggle (single button cycles: dark → light → system)
    const themeBtn = document.getElementById('theme-toggle-btn');
    themeBtn?.addEventListener('click', () => {
        const order = ['dark', 'light', 'system'];
        const cur = getPrefs().theme;
        const next = order[(order.indexOf(cur) + 1) % order.length];
        setPrefs({ theme: next });
        snack.info(`Theme: ${next}`);
    });

    // User menu
    const userBtn = document.getElementById('user-menu-btn');
    const userMenu = document.getElementById('user-menu');
    attachMenu(userBtn, userMenu);

    const userInfo = getUserInfo();
    const emailEl = document.getElementById('user-menu-email');
    if (emailEl && userInfo?.email) emailEl.textContent = userInfo.email;

    document.getElementById('logout-btn')?.addEventListener('click', () => {
        clearSession();
        resetState();
        snack.info('Signed out.');
        window.location.reload();
    });

    document.getElementById('open-change-password')?.addEventListener('click', () => go('settings'));
    document.getElementById('open-export')?.addEventListener('click', () => go('settings'));
    document.getElementById('open-delete-account')?.addEventListener('click', () => go('settings'));

    // Hamburger (mobile drawer)
    const hamburger = document.getElementById('hamburger-btn');
    const navRail = document.getElementById('nav-rail');
    const navScrim = document.getElementById('nav-rail-scrim');
    const closeRail = () => {
        navRail?.classList.remove('is-open');
        navScrim?.classList.remove('is-open');
    };
    hamburger?.addEventListener('click', () => {
        navRail?.classList.add('is-open');
        navScrim?.classList.add('is-open');
    });
    navScrim?.addEventListener('click', closeRail);
    document.querySelectorAll('.nav-rail__item').forEach(item => {
        item.addEventListener('click', closeRail);
    });

    // Global search palette
    buildIndex({
        getVaults: () => getVaults(),
        getEntries: () => getAllDecryptedEntries()
    });
    setOnSelect((result) => {
        if (result.kind === 'vault') {
            go('vaults');
        } else if (result.kind === 'entry') {
            go('vaults');
            // Open entry drawer once the page renders
            setTimeout(() => {
                import('./drawer.js').then(({ openEntryDrawer }) => openEntryDrawer(result.entry));
            }, 50);
        }
    });
    attachAppBarSearch(document.getElementById('global-search'));
    attachSearchShortcut();

    // Show Ctrl/Cmd hint based on platform
    const hint = document.getElementById('search-shortcut-hint');
    if (hint && navigator.platform?.toLowerCase().includes('mac')) hint.textContent = '⌘K';
}
