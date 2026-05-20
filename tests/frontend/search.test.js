// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, vi } from 'vitest';

beforeEach(() => {
    document.body.innerHTML = '';
    vi.resetModules();
});

describe('global search', () => {
    it('opens the palette when invoked', async () => {
        const { open, close } = await import('../../public/js/search.js');
        open();
        expect(document.querySelector('.palette')).not.toBeNull();
        close();
    });

    it('returns matching vaults from the index', async () => {
        const search = await import('../../public/js/search.js');
        const vaults = [
            { id: 1, name: 'Personal', description: '' },
            { id: 2, name: 'Acme Team', description: 'work passwords' }
        ];
        search.buildIndex({
            getVaults: () => vaults,
            getEntries: () => []
        });
        search.open();
        const input = document.querySelector('.palette__input');
        input.value = 'acme';
        input.dispatchEvent(new Event('input'));
        const results = document.querySelectorAll('.palette__result');
        expect(results.length).toBe(1);
        expect(results[0].textContent.toLowerCase()).toContain('acme team');
    });

    it('matches across vaults and entries', async () => {
        const search = await import('../../public/js/search.js');
        const v1 = { id: 1, name: 'Vault A' };
        const v2 = { id: 2, name: 'Vault B' };
        search.buildIndex({
            getVaults: () => [v1, v2],
            getEntries: () => [
                { entry: { id: 'e1', name: 'GitHub', username: 'me@github.com' }, vault: v1 },
                { entry: { id: 'e2', name: 'GitLab', username: 'me@gitlab.com' }, vault: v2 }
            ]
        });
        search.open();
        const input = document.querySelector('.palette__input');
        input.value = 'git';
        input.dispatchEvent(new Event('input'));
        const results = document.querySelectorAll('.palette__result');
        // Both entries + neither vault
        expect(results.length).toBe(2);
    });

    it('calls onSelect with the chosen result on Enter', async () => {
        const search = await import('../../public/js/search.js');
        const onSelect = vi.fn();
        const vault = { id: 1, name: 'PickMe' };
        search.buildIndex({ getVaults: () => [vault], getEntries: () => [] });
        search.setOnSelect(onSelect);
        search.open();
        const input = document.querySelector('.palette__input');
        input.value = 'pick';
        input.dispatchEvent(new Event('input'));
        input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
        expect(onSelect).toHaveBeenCalled();
        expect(onSelect.mock.calls[0][0].label).toBe('PickMe');
    });

    it('closes on Escape', async () => {
        const search = await import('../../public/js/search.js');
        search.buildIndex({ getVaults: () => [], getEntries: () => [] });
        search.open();
        expect(document.querySelector('.palette')).not.toBeNull();
        const input = document.querySelector('.palette__input');
        input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
        expect(document.querySelector('.palette')).toBeNull();
    });

    it('navigates with arrow keys', async () => {
        const search = await import('../../public/js/search.js');
        search.buildIndex({
            getVaults: () => [
                { id: 1, name: 'Alpha' },
                { id: 2, name: 'Alpine' }
            ],
            getEntries: () => []
        });
        search.open();
        const input = document.querySelector('.palette__input');
        input.value = 'alp';
        input.dispatchEvent(new Event('input'));
        const firstActive = document.querySelector('.palette__result.is-active');
        expect(firstActive.textContent.toLowerCase()).toContain('alpha');
        input.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
        const nextActive = document.querySelector('.palette__result.is-active');
        expect(nextActive.textContent.toLowerCase()).toContain('alpine');
    });
});
