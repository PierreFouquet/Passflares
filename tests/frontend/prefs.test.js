// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock api.js so loadPrefs() doesn't hit the network.
vi.mock('../../public/js/api.js', () => ({
    getPreferences: vi.fn(),
    updatePreferences: vi.fn()
}));

// Provide a controllable matchMedia
let mediaMatches = false;
beforeEach(() => {
    document.documentElement.removeAttribute('data-theme');
    document.documentElement.removeAttribute('data-density');
    document.documentElement.removeAttribute('data-shape');
    document.documentElement.removeAttribute('data-accent');
    document.body.innerHTML = '<span id="theme-toggle-icon">dark_mode</span>';
    localStorage.clear();
    mediaMatches = false;
    window.matchMedia = vi.fn().mockImplementation(() => ({
        matches: mediaMatches,
        media: '(prefers-color-scheme: dark)',
        addEventListener: vi.fn(),
        removeEventListener: vi.fn()
    }));
    vi.resetModules();
});

describe('applyPrefs', () => {
    it('sets all four data attributes on <html>', async () => {
        const { applyPrefs } = await import('../../public/js/prefs.js');
        applyPrefs({ theme: 'light', density: 'compact', shape: 'pill', accent: 'blue' });
        const html = document.documentElement;
        expect(html.dataset.theme).toBe('light');
        expect(html.dataset.density).toBe('compact');
        expect(html.dataset.shape).toBe('pill');
        expect(html.dataset.accent).toBe('blue');
    });

    it('ignores invalid values and keeps the current value', async () => {
        const { applyPrefs } = await import('../../public/js/prefs.js');
        applyPrefs({ theme: 'dark', density: 'comfortable', shape: 'rounded', accent: 'emerald' });
        applyPrefs({ theme: 'neon' });
        expect(document.documentElement.dataset.theme).toBe('dark');
    });

    it('persists to localStorage', async () => {
        const { applyPrefs, CACHE_KEY } = await import('../../public/js/prefs.js');
        applyPrefs({ theme: 'light', density: 'spacious', shape: 'sharp', accent: 'purple' });
        const cached = JSON.parse(localStorage.getItem(CACHE_KEY));
        expect(cached).toMatchObject({ theme: 'light', density: 'spacious', shape: 'sharp', accent: 'purple' });
    });

    it('updates the theme-toggle icon when applied', async () => {
        const { applyPrefs } = await import('../../public/js/prefs.js');
        applyPrefs({ theme: 'light' });
        expect(document.getElementById('theme-toggle-icon').textContent).toBe('light_mode');
        applyPrefs({ theme: 'dark' });
        expect(document.getElementById('theme-toggle-icon').textContent).toBe('dark_mode');
    });

    it('notifies listeners on change', async () => {
        const { applyPrefs, onPrefsChange } = await import('../../public/js/prefs.js');
        const fn = vi.fn();
        onPrefsChange(fn);
        applyPrefs({ theme: 'light' });
        expect(fn).toHaveBeenCalled();
    });
});

describe('resolvedTheme', () => {
    it('returns light/dark directly when set', async () => {
        const { resolvedTheme } = await import('../../public/js/prefs.js');
        expect(resolvedTheme('light')).toBe('light');
        expect(resolvedTheme('dark')).toBe('dark');
    });

    it('uses prefers-color-scheme for system theme', async () => {
        mediaMatches = true;
        const { resolvedTheme } = await import('../../public/js/prefs.js');
        expect(resolvedTheme('system')).toBe('dark');
    });

    it('uses light for system when OS prefers light', async () => {
        mediaMatches = false;
        const { resolvedTheme } = await import('../../public/js/prefs.js');
        expect(resolvedTheme('system')).toBe('light');
    });
});

describe('loadPrefs', () => {
    it('uses cached prefs when no remote', async () => {
        const { loadPrefs, CACHE_KEY } = await import('../../public/js/prefs.js');
        localStorage.setItem(CACHE_KEY, JSON.stringify({ theme: 'light', density: 'compact', shape: 'pill', accent: 'purple' }));
        await loadPrefs({ fetchRemote: false });
        expect(document.documentElement.dataset.theme).toBe('light');
        expect(document.documentElement.dataset.density).toBe('compact');
    });

    it('falls back gracefully when remote fetch fails', async () => {
        const api = await import('../../public/js/api.js');
        api.getPreferences.mockRejectedValueOnce(new Error('401'));
        const { loadPrefs } = await import('../../public/js/prefs.js');
        await loadPrefs({ fetchRemote: true }); // should not throw
        // Defaults applied
        expect(document.documentElement.dataset.theme).toBeTruthy();
    });

    it('applies remote prefs when fetch succeeds', async () => {
        const api = await import('../../public/js/api.js');
        api.getPreferences.mockResolvedValueOnce({
            theme: 'dark', density: 'spacious', shape: 'sharp', accent: 'orange'
        });
        const { loadPrefs } = await import('../../public/js/prefs.js');
        await loadPrefs({ fetchRemote: true });
        expect(document.documentElement.dataset.theme).toBe('dark');
        expect(document.documentElement.dataset.accent).toBe('orange');
    });
});

describe('setPrefs', () => {
    it('updates DOM immediately and debounces server sync', async () => {
        const api = await import('../../public/js/api.js');
        api.updatePreferences.mockResolvedValue({});
        const { setPrefs } = await import('../../public/js/prefs.js');

        vi.useFakeTimers();
        setPrefs({ theme: 'light' });
        expect(document.documentElement.dataset.theme).toBe('light');
        expect(api.updatePreferences).not.toHaveBeenCalled();

        vi.advanceTimersByTime(500);
        await Promise.resolve();
        expect(api.updatePreferences).toHaveBeenCalledWith({ theme: 'light' });
        vi.useRealTimers();
    });
});
