// Read cached preferences from localStorage and apply them to the <html>
// element BEFORE any stylesheet computes, so the first paint matches the
// user's chosen theme / density / shape / accent.
//
// Kept as an external file (instead of inline in index.html) so the page CSP
// can drop `'unsafe-inline'` from `script-src`.
(function () {
    try {
        const raw = localStorage.getItem('passflares.prefs');
        if (!raw) return;
        const p = JSON.parse(raw);
        const html = document.documentElement;
        if (p.theme)   html.dataset.theme   = p.theme;
        if (p.density) html.dataset.density = p.density;
        if (p.shape)   html.dataset.shape   = p.shape;
        if (p.accent)  html.dataset.accent  = p.accent;
    } catch {
        // Corrupt cache or unavailable storage — fall through with defaults.
    }
})();
