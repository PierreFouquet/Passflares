// public/js/search.js — global search / command palette.
// Builds an in-memory index across all loaded vaults' decrypted entries.

import { escapeHTML } from './ui.js';

let palette;
let scrim;
let input;
let resultsEl;
let activeIdx = 0;
let currentResults = [];
let providers = { vaults: () => [], entries: () => [] };
let onSelect = () => {};

function ensureMount() {
    if (palette) return;
    scrim = document.createElement('div');
    scrim.className = 'palette-scrim';
    scrim.innerHTML = `
        <div class="palette" role="dialog" aria-modal="true" aria-label="Search">
            <div class="palette__input-wrap">
                <span class="icon">search</span>
                <input type="search" class="palette__input" placeholder="Search vaults and entries…" autocomplete="off" />
            </div>
            <div class="palette__results" role="listbox"></div>
            <div class="palette__hint">
                <span><kbd>↑</kbd><kbd>↓</kbd> navigate · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close</span>
                <span data-count></span>
            </div>
        </div>
    `;
    palette = scrim.querySelector('.palette');
    input = scrim.querySelector('.palette__input');
    resultsEl = scrim.querySelector('.palette__results');

    scrim.addEventListener('click', (e) => {
        if (e.target === scrim) close();
    });
    input.addEventListener('input', () => render(input.value));
    input.addEventListener('keydown', onKey);
    // Also handle Escape at document level so it works even when focus
    // hasn't landed on the input yet.
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && scrim?.isConnected) {
            e.preventDefault();
            close();
        }
    });
}

export function buildIndex({ getVaults, getEntries }) {
    providers = { vaults: getVaults, entries: getEntries };
}

export function setOnSelect(fn) { onSelect = fn; }

function search(query) {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const vaults = providers.vaults() ?? [];
    const entries = providers.entries() ?? [];

    const out = [];
    for (const v of vaults) {
        const hay = `${v.name} ${v.description ?? ''}`.toLowerCase();
        if (hay.includes(q)) {
            out.push({ kind: 'vault', vault: v, label: v.name, sub: v.description || 'Vault' });
        }
    }
    for (const e of entries) {
        const hay = `${e.entry.name} ${e.entry.username ?? ''} ${e.entry.url ?? ''} ${e.entry.notes ?? ''}`.toLowerCase();
        if (hay.includes(q)) {
            out.push({ kind: 'entry', entry: e.entry, vault: e.vault, label: e.entry.name, sub: `${e.entry.username ?? ''} · ${e.vault.name}` });
        }
    }
    return out.slice(0, 20);
}

function render(query) {
    currentResults = search(query);
    activeIdx = 0;
    resultsEl.innerHTML = '';
    scrim.querySelector('[data-count]').textContent = currentResults.length === 0
        ? (query.trim() ? 'No matches' : '')
        : `${currentResults.length} result${currentResults.length === 1 ? '' : 's'}`;

    currentResults.forEach((r, i) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'palette__result' + (i === 0 ? ' is-active' : '');
        btn.setAttribute('role', 'option');
        const iconName = r.kind === 'vault' ? 'lock' : 'key';
        btn.innerHTML = `
            <span class="icon">${iconName}</span>
            <span class="palette__result__title">${escapeHTML(r.label)}</span>
            <span class="palette__result__meta">${escapeHTML(r.sub)}</span>
        `;
        btn.addEventListener('click', () => selectActive(i));
        btn.addEventListener('mouseenter', () => setActive(i));
        resultsEl.appendChild(btn);
    });
}

function setActive(i) {
    activeIdx = Math.max(0, Math.min(i, currentResults.length - 1));
    resultsEl.querySelectorAll('.palette__result').forEach((b, idx) => {
        b.classList.toggle('is-active', idx === activeIdx);
    });
    const el = resultsEl.children[activeIdx];
    el?.scrollIntoView({ block: 'nearest' });
}

function selectActive(i = activeIdx) {
    const r = currentResults[i];
    if (!r) return;
    close();
    onSelect(r);
}

function onKey(e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(activeIdx + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(activeIdx - 1); }
    else if (e.key === 'Enter') { e.preventDefault(); selectActive(); }
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
}

export function open() {
    ensureMount();
    if (scrim.isConnected) return;
    document.body.appendChild(scrim);
    input.value = '';
    render('');
    requestAnimationFrame(() => input.focus());
}

export function close() {
    if (!scrim?.isConnected) return;
    scrim.remove();
}

export function attachShortcut() {
    document.addEventListener('keydown', (e) => {
        const isPalette = (e.key === 'k' || e.key === 'K') && (e.ctrlKey || e.metaKey);
        if (isPalette) {
            e.preventDefault();
            if (scrim?.isConnected) close(); else open();
        }
    });
}

// Top-bar search input wiring: focus opens palette; typing is delegated.
export function attachAppBarSearch(searchEl) {
    if (!searchEl) return;
    searchEl.addEventListener('focus', open);
    searchEl.addEventListener('click', open);
    searchEl.addEventListener('keydown', (e) => {
        if (e.key !== 'Tab' && e.key !== 'Shift') open();
    });
}
