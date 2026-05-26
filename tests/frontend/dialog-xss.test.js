// @vitest-environment happy-dom
//
// Regression tests for the XSS fix in dialog.js (1.0.1).
//
// Before 1.0.1 the dialog header used template-literal interpolation for the
// title and confirmDialog wrapped the message in `<p>${message}</p>`. Any
// caller that interpolated user-controlled data (e.g. vault.name, entry.name)
// into title/message would inject markup into the dialog. After the fix both
// title and message must round-trip as text, not HTML.

import { describe, it, expect, beforeEach } from 'vitest';

beforeEach(() => {
    document.body.innerHTML = `<div id="dialog-root"></div>`;
});

describe('dialog title escaping', () => {
    it('renders the title as text, not HTML', async () => {
        const { openDialog } = await import('../../public/js/dialog.js');
        const payload = '<img src=x onerror="window.__pwn=1">';
        openDialog({ title: payload, body: 'ok', actions: [] });

        const title = document.getElementById('dialog-title');
        expect(title, 'title element should exist').not.toBeNull();
        // The payload survives as text content…
        expect(title.textContent).toBe(payload);
        // …but is NOT parsed as markup.
        expect(title.querySelector('img')).toBeNull();
        expect(window.__pwn).toBeUndefined();
    });

    it('handles a missing title without injecting "undefined"', async () => {
        const { openDialog } = await import('../../public/js/dialog.js');
        openDialog({ body: 'x', actions: [] });
        const title = document.getElementById('dialog-title');
        expect(title.textContent).toBe('');
    });
});

describe('confirmDialog message escaping', () => {
    it('renders the message as text, not HTML', async () => {
        const { confirmDialog } = await import('../../public/js/dialog.js');
        const payload = 'Remove "<img src=x onerror=\'window.__pwn2=1\'>" from this vault?';
        // Don't await — we just want the dialog to render so we can inspect it.
        confirmDialog({ title: 'Delete entry?', message: payload });

        const body = document.querySelector('.dialog__body');
        expect(body, 'body element should exist').not.toBeNull();
        expect(body.textContent).toContain('Remove');
        expect(body.querySelector('img')).toBeNull();
        expect(window.__pwn2).toBeUndefined();
    });

    it('still escapes a title containing entry names', async () => {
        const { confirmDialog } = await import('../../public/js/dialog.js');
        const vaultName = '<script>window.__pwn3=1</script>Evil';
        confirmDialog({
            title: `Delete "${vaultName}"?`,
            message: 'Are you sure?'
        });
        const title = document.getElementById('dialog-title');
        expect(title.querySelector('script')).toBeNull();
        expect(window.__pwn3).toBeUndefined();
        // The full literal title survives as text — including the angle brackets.
        expect(title.textContent).toContain('<script>');
    });
});
