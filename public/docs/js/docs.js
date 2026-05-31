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
        const btn = document.getElementById('theme-toggle-btn');
        const theme = html.dataset.theme || 'system';
        if (theme === 'system') {
            icon.textContent = 'brightness_auto';
            if (btn) btn.title = `Theme: system (${resolvedTheme(theme)})`;
        } else {
            icon.textContent = resolvedTheme(theme) === 'dark' ? 'dark_mode' : 'light_mode';
            if (btn) btn.title = `Theme: ${theme}`;
        }
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

    // Highlight the current page in the nav. Normalise both the current path
    // and each link's resolved path to a canonical key (drop index.html, the
    // .html extension, and any trailing slash) so highlighting works whether
    // or not the server strips extensions or adds a trailing slash.
    const canon = (path) => path.replace(/index\.html$/, '').replace(/\.html$/, '').replace(/\/$/, '');
    const here = canon(location.pathname);
    document.querySelectorAll('.docs-bar__nav a').forEach(a => {
        a.classList.toggle('is-active', canon(a.pathname) === here);
    });

    // Respond to OS theme flip when on `system`.
    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', () => {
            if ((html.dataset.theme || 'system') === 'system') updateThemeIcon();
        });
    }

    updateThemeIcon();
})();
