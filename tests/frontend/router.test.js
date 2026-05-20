// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from 'vitest';

beforeEach(async () => {
    vi.resetModules();
    document.body.innerHTML = `
        <nav>
            <a class="nav-rail__item" data-nav="home"></a>
            <a class="nav-rail__item" data-nav="vaults"></a>
            <a class="nav-rail__item" data-nav="settings"></a>
        </nav>
        <div id="mount"></div>
    `;
    history.replaceState(null, '', '/');
    location.hash = '';
});

describe('router', () => {
    it('renders the route matching the hash', async () => {
        const router = await import('../../public/js/router.js');
        const home = vi.fn(({ mount }) => { mount.innerHTML = '<h1>Home</h1>'; });
        const vaults = vi.fn(({ mount }) => { mount.innerHTML = '<h1>Vaults</h1>'; });
        router.setMountElement(document.getElementById('mount'));
        router.registerRoute('home', home);
        router.registerRoute('vaults', vaults);
        await router.start({ defaultRoute: 'home' });
        expect(home).toHaveBeenCalled();
        expect(document.getElementById('mount').textContent).toContain('Home');
    });

    it('updates content when hash changes', async () => {
        const router = await import('../../public/js/router.js');
        router.setMountElement(document.getElementById('mount'));
        router.registerRoute('home',   ({ mount }) => { mount.innerHTML = 'HOME'; });
        router.registerRoute('vaults', ({ mount }) => { mount.innerHTML = 'VAULTS'; });
        await router.start({ defaultRoute: 'home' });
        expect(document.getElementById('mount').textContent).toBe('HOME');

        location.hash = '#/vaults';
        window.dispatchEvent(new HashChangeEvent('hashchange'));
        await Promise.resolve();
        await new Promise(r => setTimeout(r, 0));
        expect(document.getElementById('mount').textContent).toBe('VAULTS');
    });

    it('falls back to the registered fallback for unknown routes', async () => {
        const router = await import('../../public/js/router.js');
        router.setMountElement(document.getElementById('mount'));
        const fallback = vi.fn(({ mount }) => { mount.innerHTML = 'FALLBACK'; });
        router.registerFallback(fallback);
        location.hash = '#/does-not-exist';
        await router.start({ defaultRoute: 'home' });
        expect(fallback).toHaveBeenCalled();
    });

    it('marks the active nav rail item based on the route', async () => {
        const router = await import('../../public/js/router.js');
        router.setMountElement(document.getElementById('mount'));
        router.registerRoute('vaults', ({ mount }) => { mount.innerHTML = ''; });
        location.hash = '#/vaults';
        await router.start({ defaultRoute: 'home' });
        const active = document.querySelector('.nav-rail__item.is-active');
        expect(active?.dataset.nav).toBe('vaults');
    });

    it('renders an error pane if a route throws', async () => {
        const router = await import('../../public/js/router.js');
        router.setMountElement(document.getElementById('mount'));
        router.registerRoute('home', () => { throw new Error('Boom'); });
        await router.start({ defaultRoute: 'home' });
        expect(document.getElementById('mount').textContent).toContain('Boom');
    });
});
