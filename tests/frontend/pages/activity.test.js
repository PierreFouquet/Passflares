// @vitest-environment happy-dom
//
// Settings → Recent activity, the read side of the audit log (#73).
//
// The panel's job is telling someone whether their account has been touched by
// anyone else, so the properties that matter are: attacker-influenced payload
// fields are never interpolated as HTML, and a failed fetch is never rendered
// as "nothing happened".

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const html = readFileSync(resolve('public/index.html'), 'utf8');

/** Loads the two templates the panel needs into the document. */
function installTemplates() {
    for (const id of ['tpl-page-settings', 'tpl-activity-row']) {
        const match = html.match(new RegExp(`<template id="${id}">([\\s\\S]*?)</template>`));
        if (!match) throw new Error(`template ${id} not found in public/index.html`);
        const tpl = document.createElement('template');
        tpl.id = id;
        tpl.innerHTML = match[1];
        document.body.appendChild(tpl);
    }
}

const getAuditLog = vi.fn();

vi.mock('../../../public/js/api.js', () => ({
    getAuditLog: (...args) => getAuditLog(...args),
    getTotpStatus: vi.fn(async () => ({ enabled: false, remainingRecoveryCodes: 0 })),
    enrollTotp: vi.fn(), enableTotp: vi.fn(), disableTotp: vi.fn(),
    regenerateRecoveryCodes: vi.fn(), deleteAccount: vi.fn(),
    loadEncryptedVaultData: vi.fn(), getVaults: vi.fn(async () => [])
}));
vi.mock('../../../public/js/prefs.js', () => ({
    getPrefs: () => ({ theme: 'system', density: 'comfortable', shape: 'rounded', accent: 'emerald' }),
    setPrefs: vi.fn(),
    ALLOWED: { theme: [], density: [], shape: [], accent: [] }
}));
vi.mock('../../../public/js/session.js', () => ({
    getUserInfo: () => ({ email: 'u@example.com', userId: 1 }),
    clearSession: vi.fn()
}));
vi.mock('../../../public/js/state.js', () => ({
    reset: vi.fn(), hasPrivateKey: () => true, getWrappedPrivateKey: () => null, getVaults: () => []
}));
vi.mock('../../../public/js/snackbar.js', () => ({ snack: { success: vi.fn(), error: vi.fn() } }));
vi.mock('../../../public/js/dialog.js', () => ({ confirmDialog: vi.fn(), openDialog: vi.fn() }));
vi.mock('../../../public/js/auth-flow.js', () => ({
    deriveExistingHierarchy: vi.fn(), rotateMasterPassword: vi.fn()
}));
vi.mock('../../../public/js/clipboard.js', () => ({ copyToClipboard: vi.fn() }));

let renderSettingsPage;

beforeEach(async () => {
    document.body.innerHTML = '';
    installTemplates();
    getAuditLog.mockReset();
    ({ renderSettingsPage } = await import('../../../public/js/pages/settings.js'));
});

afterEach(() => {
    vi.restoreAllMocks();
});

/** Renders the settings page and waits for the activity fetch to settle. */
async function render() {
    const mount = document.createElement('div');
    document.body.appendChild(mount);
    renderSettingsPage({ mount });
    await new Promise(r => setTimeout(r, 0));
    await new Promise(r => setTimeout(r, 0));
    return mount;
}

const event = (over = {}) => ({
    action: 'LOGIN_SUCCESS',
    timestamp: '2026-08-01T10:00:00.000Z',
    ipAddress: '203.0.113.1',
    userAgent: 'Mozilla/5.0',
    detail: {},
    ...over
});

describe('Recent activity panel', () => {
    it('lists the account’s events with a human-readable label', async () => {
        getAuditLog.mockResolvedValue({ events: [event()], nextBefore: null, retentionDays: 90 });
        const mount = await render();

        const rows = mount.querySelectorAll('[data-activity-list] .list-row');
        expect(rows).toHaveLength(1);
        expect(rows[0].querySelector('[data-activity-action]').textContent).toBe('Signed in');
        expect(rows[0].querySelector('[data-activity-ip]').textContent).toBe('203.0.113.1');
    });

    it('surfaces failed sign-ins — the reason the panel exists', async () => {
        getAuditLog.mockResolvedValue({
            events: [event({ action: 'LOGIN_FAILURE', ipAddress: '198.51.100.9' })],
            nextBefore: null, retentionDays: 90
        });
        const mount = await render();

        const row = mount.querySelector('[data-activity-list] .list-row');
        expect(row.querySelector('[data-activity-action]').textContent).toMatch(/failed sign-in/i);
    });

    // Audit payloads carry attacker-influenced values: the email from a failed
    // sign-in, a User-Agent, an IP header. None may reach innerHTML.
    it('never interpolates an event field as HTML', async () => {
        getAuditLog.mockResolvedValue({
            events: [event({ ipAddress: '<img src=x onerror=alert(1)>' })],
            nextBefore: null, retentionDays: 90
        });
        const mount = await render();

        const list = mount.querySelector('[data-activity-list]');
        expect(list.querySelector('img')).toBeNull();
        expect(list.querySelector('[data-activity-ip]').textContent).toBe('<img src=x onerror=alert(1)>');
    });

    it('skips actions it has no label for, rather than showing an internal name', async () => {
        getAuditLog.mockResolvedValue({
            events: [event({ action: 'SOME_INTERNAL_ACTION_V2' }), event()],
            nextBefore: null, retentionDays: 90
        });
        const mount = await render();

        const rows = mount.querySelectorAll('[data-activity-list] .list-row');
        expect(rows).toHaveLength(1);
        expect(mount.querySelector('[data-activity-list]').textContent).not.toMatch(/SOME_INTERNAL_ACTION/);
    });

    // The important negative case: a failed fetch rendered as an empty list
    // reads as "your account is untouched", which is the opposite of the truth.
    it('reports a load failure instead of showing an empty list', async () => {
        getAuditLog.mockRejectedValue(new Error('network'));
        const mount = await render();

        const hint = mount.querySelector('[data-activity-hint]').textContent;
        expect(hint).toMatch(/could not load/i);
        expect(hint).not.toMatch(/no account activity/i);
    });

    it('says so plainly when there genuinely are no events', async () => {
        getAuditLog.mockResolvedValue({ events: [], nextBefore: null, retentionDays: 90 });
        const mount = await render();

        expect(mount.querySelector('[data-activity-hint]').textContent).toMatch(/no account activity/i);
    });

    it('states the retention window so an absent event is not misread', async () => {
        getAuditLog.mockResolvedValue({ events: [event()], nextBefore: null, retentionDays: 90 });
        const mount = await render();

        expect(mount.querySelector('[data-activity-hint]').textContent).toMatch(/90 days/);
    });

    it('hides "Show more" when the log is exhausted', async () => {
        getAuditLog.mockResolvedValue({ events: [event()], nextBefore: null, retentionDays: 90 });
        const mount = await render();

        expect(mount.querySelector('[data-action="activity-more"]').classList.contains('hidden')).toBe(true);
    });

    it('pages with a keyset cursor rather than an offset', async () => {
        getAuditLog
            .mockResolvedValueOnce({
                events: [event()], nextBefore: '2026-08-01T09:00:00.000Z', retentionDays: 90
            })
            .mockResolvedValueOnce({
                events: [event({ action: 'TOTP_ENABLED', timestamp: '2026-08-01T08:00:00.000Z' })],
                nextBefore: null, retentionDays: 90
            });

        const mount = await render();
        const moreBtn = mount.querySelector('[data-action="activity-more"]');
        expect(moreBtn.classList.contains('hidden')).toBe(false);

        moreBtn.click();
        await new Promise(r => setTimeout(r, 0));

        expect(getAuditLog).toHaveBeenLastCalledWith(
            expect.objectContaining({ before: '2026-08-01T09:00:00.000Z' })
        );
        expect(mount.querySelectorAll('[data-activity-list] .list-row')).toHaveLength(2);
        expect(moreBtn.classList.contains('hidden')).toBe(true);
    });
});
