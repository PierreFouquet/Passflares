// docs.js — light-weight enhancements for the docs site.
// Reads/writes the same `passflares.prefs` localStorage cache the main app
// uses, so theme + accent + density + shape stay in sync between sites.

(function () {
    const CACHE_KEY = 'passflares.prefs';
    const html = document.documentElement;

    function readCache() {
        try {
            const raw = localStorage.getItem(CACHE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch { return null; }
    }

    function writeCache(prefs) {
        try { localStorage.setItem(CACHE_KEY, JSON.stringify(prefs)); } catch {}
    }

    function resolvedTheme(theme) {
        if (theme === 'light' || theme === 'dark') return theme;
        if (!window.matchMedia) return 'dark';
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function updateThemeIcon() {
        const icon = document.getElementById('theme-toggle-icon');
        if (!icon) return;
        icon.textContent = resolvedTheme(html.dataset.theme) === 'dark' ? 'dark_mode' : 'light_mode';
    }

    // Theme toggle: cycles light → dark → system → light.
    const btn = document.getElementById('theme-toggle-btn');
    if (btn) {
        btn.addEventListener('click', () => {
            const order = ['light', 'dark', 'system'];
            const current = html.dataset.theme || 'system';
            const next = order[(order.indexOf(current) + 1) % order.length];
            html.dataset.theme = next;
            const prefs = readCache() || {};
            prefs.theme = next;
            writeCache(prefs);
            updateThemeIcon();
        });
    }

    // Highlight the current page in the nav.
    const here = location.pathname.split('/').pop() || 'docs.html';
    document.querySelectorAll('.docs-bar__nav a').forEach(a => {
        const target = a.getAttribute('href');
        if (target === here) a.classList.add('is-active');
        else a.classList.remove('is-active');
    });

    // Respond to OS theme flip when on `system`.
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', () => {
            if ((html.dataset.theme || 'system') === 'system') updateThemeIcon();
        });
    }

    updateThemeIcon();
})();
