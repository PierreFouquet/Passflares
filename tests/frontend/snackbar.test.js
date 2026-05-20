// @vitest-environment happy-dom
import { describe, it, expect, beforeEach, vi } from 'vitest';

beforeEach(async () => {
    document.body.innerHTML = `<div id="snackbar-host" class="snackbar-host"></div>`;
    vi.resetModules();
});

describe('snackbar', () => {
    it('appends a toast to the host', async () => {
        const { snack } = await import('../../public/js/snackbar.js');
        snack.success('Saved');
        const toast = document.querySelector('.snackbar--success');
        expect(toast).not.toBeNull();
        expect(toast.textContent).toContain('Saved');
    });

    it('uses the right variant class for each type', async () => {
        const { snack } = await import('../../public/js/snackbar.js');
        snack.info('Hi');
        snack.warning('Careful');
        snack.error('Bad');
        expect(document.querySelector('.snackbar--info')).not.toBeNull();
        expect(document.querySelector('.snackbar--warning')).not.toBeNull();
        expect(document.querySelector('.snackbar--error')).not.toBeNull();
    });

    it('dismisses on close-button click', async () => {
        const { snack } = await import('../../public/js/snackbar.js');
        snack.info('Hello');
        document.querySelector('.snackbar__close').click();
        // is-closing class added; removal is animated
        expect(document.querySelector('.snackbar.is-closing')).not.toBeNull();
    });

    it('returns null when message is empty', async () => {
        const { showSnack } = await import('../../public/js/snackbar.js');
        const result = showSnack({ message: '', type: 'info' });
        expect(result).toBeNull();
    });

    it('escapes HTML in the message', async () => {
        const { snack } = await import('../../public/js/snackbar.js');
        snack.error('<img src=x onerror=alert(1)>');
        const body = document.querySelector('.snackbar__body');
        // Should be inserted as escaped text — innerHTML contains &lt; etc.
        expect(body.innerHTML).not.toContain('<img');
        expect(body.textContent).toContain('<img');
    });

    it('auto-dismisses after duration', async () => {
        vi.useFakeTimers();
        const { snack } = await import('../../public/js/snackbar.js');
        snack.success('Yay', { duration: 100 });
        expect(document.querySelector('.snackbar--success')).not.toBeNull();
        vi.advanceTimersByTime(120);
        expect(document.querySelector('.snackbar.is-closing')).not.toBeNull();
        vi.useRealTimers();
    });
});
