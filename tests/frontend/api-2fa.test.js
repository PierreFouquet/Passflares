// @vitest-environment happy-dom
// Covers the client API wrappers for the two-factor (TOTP) endpoints, including
// the suppressAuthRedirect behaviour that keeps a wrong 2FA code from wiping the
// session / reloading the page mid-dialog.
import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockFetch = vi.fn();
global.fetch = mockFetch;

vi.mock('../../public/js/session.js', () => ({
    getAuthHeaders: () => ({ 'Content-Type': 'application/json', Authorization: 'Bearer test-token' }),
    clearSession: vi.fn(),
    getSessionToken: () => 'test-token'
}));

vi.mock('../../public/js/constants.js', () => ({
    API_BASE_URL: '/api'
}));

import {
    verifyLogin2fa,
    getTotpStatus,
    enrollTotp,
    enableTotp,
    disableTotp,
    regenerateRecoveryCodes
} from '../../public/js/api.js';
import { clearSession } from '../../public/js/session.js';

function mockOk(body, status = 200) {
    mockFetch.mockResolvedValueOnce({ ok: true, status, json: () => Promise.resolve(body) });
}

function mockErr(status, message) {
    mockFetch.mockResolvedValueOnce({
        ok: false,
        status,
        statusText: 'Error',
        text: () => Promise.resolve(JSON.stringify({ message }))
    });
}

beforeEach(() => {
    mockFetch.mockReset();
    clearSession.mockClear();
});

describe('verifyLogin2fa', () => {
    it('POSTs the temp token + code to /api/login/2fa without an auth header', async () => {
        mockOk({ token: 'session', userId: 1, email: 'u@example.com', encryptionSalt: 'salt' });
        await verifyLogin2fa('temp-token', '123456');
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/login/2fa',
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({ tempToken: 'temp-token', code: '123456' })
            })
        );
        // needsAuth=false → no Authorization header.
        const [, cfg] = mockFetch.mock.calls[0];
        expect(cfg.headers.Authorization).toBeUndefined();
    });

    it('does NOT clear the session or reload on a 401 (suppressAuthRedirect)', async () => {
        const reload = vi.fn();
        vi.stubGlobal('alert', vi.fn());
        vi.stubGlobal('location', { reload });
        mockErr(401, 'Invalid code.');

        await expect(verifyLogin2fa('temp-token', '000000')).rejects.toThrow('Invalid code.');
        expect(clearSession).not.toHaveBeenCalled();
        expect(reload).not.toHaveBeenCalled();
        vi.unstubAllGlobals();
    });
});

describe('getTotpStatus', () => {
    it('GETs /api/2fa/status', async () => {
        mockOk({ enabled: true, remainingRecoveryCodes: 7 });
        const res = await getTotpStatus();
        expect(mockFetch).toHaveBeenCalledWith('/api/2fa/status', expect.objectContaining({ method: 'GET' }));
        expect(res.remainingRecoveryCodes).toBe(7);
    });
});

describe('enrollTotp', () => {
    it('POSTs an empty body for a first-time enrollment', async () => {
        mockOk({ secret: 'ABC', otpauthUri: 'otpauth://x', qrDataUri: 'data:image/svg+xml;base64,zzz' });
        await enrollTotp();
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/2fa/enroll',
            expect.objectContaining({ method: 'POST', body: JSON.stringify({}) })
        );
    });

    it('POSTs the re-auth payload when changing authenticator', async () => {
        mockOk({ secret: 'ABC', qrDataUri: 'data:...' });
        await enrollTotp({ masterPassword: 'pw', code: '123456' });
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/2fa/enroll',
            expect.objectContaining({ body: JSON.stringify({ masterPassword: 'pw', code: '123456' }) })
        );
    });

    it('surfaces a 401 without clearing the session', async () => {
        const reload = vi.fn();
        vi.stubGlobal('alert', vi.fn());
        vi.stubGlobal('location', { reload });
        mockErr(401, 'Master password is incorrect.');
        await expect(enrollTotp({ masterPassword: 'bad', code: '1' })).rejects.toThrow('Master password is incorrect.');
        expect(clearSession).not.toHaveBeenCalled();
        expect(reload).not.toHaveBeenCalled();
        vi.unstubAllGlobals();
    });
});

describe('enableTotp', () => {
    it('POSTs the code to /api/2fa/enable', async () => {
        mockOk({ enabled: true, recoveryCodes: ['AAAAA-BBBBB'] });
        const res = await enableTotp('123456');
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/2fa/enable',
            expect.objectContaining({ method: 'POST', body: JSON.stringify({ code: '123456' }) })
        );
        expect(res.recoveryCodes).toHaveLength(1);
    });
});

describe('disableTotp', () => {
    it('POSTs master password + code to /api/2fa/disable', async () => {
        mockOk({ disabled: true });
        await disableTotp('pw', '123456');
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/2fa/disable',
            expect.objectContaining({ method: 'POST', body: JSON.stringify({ masterPassword: 'pw', code: '123456' }) })
        );
    });
});

describe('regenerateRecoveryCodes', () => {
    it('POSTs the master password to /api/2fa/recovery-codes/regenerate', async () => {
        mockOk({ recoveryCodes: ['AAAAA-BBBBB', 'CCCCC-DDDDD'] });
        const res = await regenerateRecoveryCodes('pw');
        expect(mockFetch).toHaveBeenCalledWith(
            '/api/2fa/recovery-codes/regenerate',
            expect.objectContaining({ method: 'POST', body: JSON.stringify({ masterPassword: 'pw' }) })
        );
        expect(res.recoveryCodes).toHaveLength(2);
    });
});
