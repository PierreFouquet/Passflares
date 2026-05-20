// public/js/menu.js — dropdown menu controller.

export function attachMenu(triggerEl, menuEl) {
    if (!triggerEl || !menuEl) return;

    const open = () => {
        menuEl.classList.remove('hidden');
        triggerEl.setAttribute('aria-expanded', 'true');
        document.addEventListener('click', onOutsideClick, { capture: true });
        document.addEventListener('keydown', onKeyDown);
    };
    const close = () => {
        menuEl.classList.add('hidden');
        triggerEl.setAttribute('aria-expanded', 'false');
        document.removeEventListener('click', onOutsideClick, { capture: true });
        document.removeEventListener('keydown', onKeyDown);
    };
    const isOpen = () => !menuEl.classList.contains('hidden');
    const toggle = () => (isOpen() ? close() : open());

    function onOutsideClick(e) {
        if (menuEl.contains(e.target) || triggerEl.contains(e.target)) return;
        close();
    }
    function onKeyDown(e) {
        if (e.key === 'Escape') close();
    }

    triggerEl.addEventListener('click', (e) => {
        e.stopPropagation();
        toggle();
    });

    // Close after a menu item click
    menuEl.addEventListener('click', (e) => {
        if (e.target.closest('.menu__item')) close();
    });

    return { open, close, toggle, isOpen };
}
