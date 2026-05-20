// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock clipboard to avoid touching navigator.clipboard
vi.mock('../../public/js/clipboard.js', () => ({ copyToClipboard: vi.fn() }));
// Snackbar host required by clipboard's snack.success but mocked
vi.mock('../../public/js/snackbar.js', () => ({ snack: { success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }, showSnack: vi.fn() }));

beforeEach(() => {
    document.body.innerHTML = `
        <aside id="entry-drawer" class="entry-drawer" aria-hidden="true"></aside>
        <div id="entry-drawer-scrim" class="entry-drawer-scrim"></div>

        <template id="tpl-entry-drawer-body">
            <div class="entry-drawer__header">
                <h3 class="entry-drawer__title" data-name></h3>
                <button type="button" class="icon-btn" data-close><span class="icon">close</span></button>
            </div>
            <div class="entry-drawer__body">
                <span data-username></span>
                <span data-password></span>
                <button type="button" class="icon-btn" data-toggle-password><span class="icon">visibility</span></button>
                <button type="button" class="icon-btn" data-copy-username></button>
                <button type="button" class="icon-btn" data-copy-password></button>
                <div data-url-section hidden><a data-url></a></div>
                <div data-notes-section hidden><div data-notes></div></div>
            </div>
            <div class="entry-drawer__footer">
                <button type="button" data-delete></button>
                <button type="button" data-close></button>
            </div>
        </template>
    `;
    vi.resetModules();
});

const sampleEntry = {
    id: 'e1', name: 'Acme login', username: 'me@acme.com', password: 'topsecret',
    url: 'https://acme.com', notes: 'careful here'
};

describe('openEntryDrawer', () => {
    it('opens with the entry data populated', async () => {
        const { openEntryDrawer } = await import('../../public/js/drawer.js');
        openEntryDrawer(sampleEntry);
        const drawer = document.getElementById('entry-drawer');
        expect(drawer.classList.contains('is-open')).toBe(true);
        expect(drawer.querySelector('[data-name]').textContent).toBe('Acme login');
        expect(drawer.querySelector('[data-username]').textContent).toBe('me@acme.com');
    });

    it('masks the password by default and reveals on toggle', async () => {
        const { openEntryDrawer } = await import('../../public/js/drawer.js');
        openEntryDrawer(sampleEntry);
        const pwd = document.querySelector('[data-password]');
        expect(pwd.textContent).not.toContain('topsecret');
        document.querySelector('[data-toggle-password]').click();
        expect(pwd.textContent).toBe('topsecret');
    });

    it('renders the URL section when url present', async () => {
        const { openEntryDrawer } = await import('../../public/js/drawer.js');
        openEntryDrawer(sampleEntry);
        const urlSection = document.querySelector('[data-url-section]');
        expect(urlSection.hidden).toBe(false);
        expect(document.querySelector('[data-url]').textContent).toContain('acme.com');
    });

    it('hides url + notes sections when absent', async () => {
        const { openEntryDrawer } = await import('../../public/js/drawer.js');
        openEntryDrawer({ id: 'e2', name: 'No extras', username: 'u', password: 'p' });
        expect(document.querySelector('[data-url-section]').hidden).toBe(true);
        expect(document.querySelector('[data-notes-section]').hidden).toBe(true);
    });

    it('closes on Escape key', async () => {
        const { openEntryDrawer } = await import('../../public/js/drawer.js');
        openEntryDrawer(sampleEntry);
        expect(document.getElementById('entry-drawer').classList.contains('is-open')).toBe(true);
        document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
        expect(document.getElementById('entry-drawer').classList.contains('is-open')).toBe(false);
    });

    it('invokes onDelete callback when delete button clicked', async () => {
        const { openEntryDrawer } = await import('../../public/js/drawer.js');
        const onDelete = vi.fn();
        openEntryDrawer(sampleEntry, { onDelete });
        document.querySelector('[data-delete]').click();
        expect(onDelete).toHaveBeenCalledWith(sampleEntry);
    });

    it('copies username when copy button clicked', async () => {
        const { copyToClipboard } = await import('../../public/js/clipboard.js');
        const { openEntryDrawer } = await import('../../public/js/drawer.js');
        openEntryDrawer(sampleEntry);
        document.querySelector('[data-copy-username]').click();
        expect(copyToClipboard).toHaveBeenCalledWith('me@acme.com');
    });
});
