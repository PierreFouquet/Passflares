// public/js/router.js — tiny hash-based router for the app shell.

const routes = new Map();
let fallback = null;
let mountEl = null;
let currentRouteName = null;

export function registerRoute(name, mount) {
    routes.set(name, mount);
}

export function registerFallback(mount) {
    fallback = mount;
}

export function setMountElement(el) {
    mountEl = el;
}

export function currentRoute() {
    return currentRouteName;
}

function parseHash() {
    const raw = location.hash.replace(/^#\/?/, '');
    const [name, ...rest] = raw.split('/');
    return { name: name || 'home', rest };
}

export async function go(name, opts = {}) {
    const hash = `#/${name}`;
    if (location.hash !== hash) {
        if (opts.replace) location.replace(hash);
        else location.hash = hash;
        return;
    }
    // Hash already matches → run mount manually (e.g. on first load)
    await renderCurrent();
}

async function renderCurrent() {
    if (!mountEl) return;
    const { name, rest } = parseHash();
    const mount = routes.get(name) ?? fallback;
    if (!mount) return;

    currentRouteName = name;
    mountEl.innerHTML = '';

    // Re-apply animation class for transition
    mountEl.classList.remove('page-container');
    void mountEl.offsetWidth;
    mountEl.classList.add('page-container');

    try {
        await mount({ params: rest, mount: mountEl });
    } catch (err) {
        console.error(`Route "${name}" failed to render:`, err);
        mountEl.innerHTML = `<div class="empty-state"><span class="icon">error</span><h3>Something went wrong</h3><p>${err?.message ?? 'Try refreshing the page.'}</p></div>`;
    }

    syncNavRailActive(name);
}

function syncNavRailActive(name) {
    document.querySelectorAll('.nav-rail__item').forEach(el => {
        el.classList.toggle('is-active', el.dataset.nav === name);
    });
}

export function start({ defaultRoute = 'home' } = {}) {
    if (!location.hash) location.replace(`#/${defaultRoute}`);
    window.addEventListener('hashchange', renderCurrent);
    return renderCurrent();
}
