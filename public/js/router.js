// public/js/router.js — tiny hash-based router for the app shell.

const routes = new Map();
let fallback = null;
let mountEl = null;
let currentRouteName = null;

function buildErrorState(message) {
    const wrap = document.createElement('div');
    wrap.className = 'empty-state';
    const icon = document.createElement('span');
    icon.className = 'icon';
    icon.textContent = 'error';
    const h = document.createElement('h3');
    h.textContent = 'Something went wrong';
    const p = document.createElement('p');
    p.textContent = message;
    wrap.append(icon, h, p);
    return wrap;
}

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
        // Pass `name` as a separate argument rather than interpolating it
        // into the format-string position. Avoids the CodeQL js/tainted-
        // format-string finding: console.error treats the first argument
        // as a printf-style format, so a `name` containing `%s`/`%d` would
        // consume the next argument (here `err`) as a placeholder value.
        console.error('Route failed to render:', name, err);
        // Build via DOM APIs so err.message (which can include any string a
        // page renderer rejected with — potentially derived from API or user
        // data) cannot inject markup into the error state.
        mountEl.replaceChildren(buildErrorState(err?.message ?? 'Try refreshing the page.'));
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
