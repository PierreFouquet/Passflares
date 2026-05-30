import { test, expect, gotoAndSeedLogin } from './fixtures';
import type { Page } from '@playwright/test';

// Mutable 2FA state shared by the route handlers within a single test.
interface TotpState { enabled: boolean; remaining: number }

function makeCodes(n = 10): string[] {
    return Array.from({ length: n }, (_, i) => `CODE${i}A-CODE${i}B`);
}

// Registers 2FA endpoint mocks. Registered from the test body, so they take
// precedence over the fixture's catch-all `**/api/**` route.
async function mock2fa(page: Page, state: TotpState) {
    const json = (body: unknown, status = 200) =>
        ({ status, contentType: 'application/json', body: JSON.stringify(body) });

    await page.route('**/api/2fa/status', (route) =>
        route.fulfill(json({ enabled: state.enabled, remainingRecoveryCodes: state.remaining })));

    await page.route('**/api/2fa/enroll', (route) =>
        route.fulfill(json({
            secret: 'JBSWY3DPEHPK3PXP',
            otpauthUri: 'otpauth://totp/Passflares:tester@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Passflares',
            qrDataUri: 'data:image/svg+xml;base64,PHN2Zy8+'
        })));

    await page.route('**/api/2fa/enable', (route) => {
        if (state.enabled) return route.fulfill(json({ changed: true, message: 'Authenticator updated.' }));
        state.enabled = true;
        state.remaining = 10;
        return route.fulfill(json({ enabled: true, recoveryCodes: makeCodes() }));
    });

    await page.route('**/api/2fa/disable', (route) => {
        state.enabled = false;
        state.remaining = 0;
        return route.fulfill(json({ disabled: true }));
    });

    await page.route('**/api/2fa/recovery-codes/regenerate', (route) =>
        route.fulfill(json({ recoveryCodes: makeCodes() })));
}

// Fills the login form and injects a Turnstile token (the widget script is
// external and doesn't run under the hermetic static server).
async function submitLogin(page: Page) {
    await page.fill('#login-email', 'tester@example.com');
    await page.fill('#login-master-password', 'Master-Password-123');
    await page.locator('#login-form').evaluate((form: HTMLFormElement) => {
        let i = form.querySelector('input[name="cf-turnstile-response"]') as HTMLInputElement | null;
        if (!i) {
            i = document.createElement('input');
            i.type = 'hidden';
            i.name = 'cf-turnstile-response';
            form.appendChild(i);
        }
        i.value = 'test-turnstile-token';
    });
    await page.locator('#login-form button[type="submit"]').click();
}

const SESSION_BODY = JSON.stringify({
    message: 'Login successful.',
    userId: 1,
    email: 'tester@example.com',
    encryptionSalt: 'aabbccddeeff00112233445566778899',
    token: 'fake-test-jwt'
});

test.describe('Login with 2FA', () => {
    test('login WITHOUT 2FA goes straight to the app', async ({ mockedPage: page }) => {
        // Default fixture /api/login returns a session (no requires2FA).
        await page.goto('/');
        await submitLogin(page);
        await expect(page.locator('#app-shell')).toBeVisible();
        await expect(page.locator('#auth-screen')).toBeHidden();
        await expect(page.locator('.dialog__title')).toHaveCount(0);
    });

    test('login WITH 2FA prompts for a code, then enters the app', async ({ mockedPage: page }) => {
        await page.route('**/api/login', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ requires2FA: true, tempToken: 'temp-token-abc' }) }));
        await page.route('**/api/login/2fa', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: SESSION_BODY }));

        await page.goto('/');
        await submitLogin(page);

        // Second-factor dialog appears; the app is still gated.
        await expect(page.locator('.dialog__title')).toHaveText('Two-factor authentication');
        await expect(page.locator('#app-shell')).toBeHidden();

        await page.fill('#totp-code', '123456');
        await page.locator('.dialog__actions .btn--filled').click();

        await expect(page.locator('#app-shell')).toBeVisible();
        await expect(page.locator('#auth-screen')).toBeHidden();
    });

    test('login WITH 2FA can switch to a recovery-code entry', async ({ mockedPage: page }) => {
        await page.route('**/api/login', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ requires2FA: true, tempToken: 'temp-token-abc' }) }));
        await page.route('**/api/login/2fa', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json', body: SESSION_BODY }));

        await page.goto('/');
        await submitLogin(page);

        await expect(page.locator('.dialog')).toBeVisible();
        await page.getByRole('button', { name: 'Use a recovery code instead' }).click();
        await expect(page.locator('label[for="totp-code"]')).toHaveText('Recovery code');

        await page.fill('#totp-code', 'CODE0A-CODE0B');
        await page.locator('.dialog__actions .btn--filled').click();
        await expect(page.locator('#app-shell')).toBeVisible();
    });

    test('a wrong code keeps the dialog open and the session intact', async ({ mockedPage: page }) => {
        await page.route('**/api/login', (route) =>
            route.fulfill({ status: 200, contentType: 'application/json',
                body: JSON.stringify({ requires2FA: true, tempToken: 'temp-token-abc' }) }));
        await page.route('**/api/login/2fa', (route) =>
            route.fulfill({ status: 401, contentType: 'application/json',
                body: JSON.stringify({ message: 'Invalid code.' }) }));

        await page.goto('/');
        await submitLogin(page);
        await page.fill('#totp-code', '000000');
        await page.locator('.dialog__actions .btn--filled').click();

        // Dialog stays open (no auto-logout/redirect), app still gated.
        await expect(page.locator('.dialog')).toBeVisible();
        await expect(page.locator('#app-shell')).toBeHidden();
        await expect(page.locator('#auth-screen')).toBeVisible();
    });
});

test.describe('Settings — managing 2FA', () => {
    async function openSettings(page: Page, state: TotpState, isMobile: boolean) {
        await mock2fa(page, state);
        await gotoAndSeedLogin(page);
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();
        await expect(page.locator('[data-totp-section]')).toBeVisible();
    }

    test('shows the disabled state with an Enable button', async ({ mockedPage: page, isMobile }) => {
        await openSettings(page, { enabled: false, remaining: 0 }, isMobile);
        await expect(page.locator('[data-totp-status]')).toContainText('Disabled');
        await expect(page.locator('[data-action="totp-enable"]')).toBeVisible();
        await expect(page.locator('[data-action="totp-disable"]')).toBeHidden();
    });

    test('enrolls: QR → verify → recovery codes → enabled', async ({ mockedPage: page, isMobile }) => {
        const state = { enabled: false, remaining: 0 };
        await openSettings(page, state, isMobile);

        await page.locator('[data-action="totp-enable"]').click();
        await expect(page.locator('.dialog')).toBeVisible();

        // Step 1: start enrollment → QR + secret appear.
        await page.locator('.dialog__actions .btn--filled').click();
        await expect(page.locator('img.totp-qr')).toBeVisible();
        await expect(page.locator('.totp-secret')).toContainText('JBSWY3DPEHPK3PXP');

        // Step 2: enter a code → recovery codes are shown once.
        await page.fill('#totp-verify', '123456');
        await page.locator('.dialog__actions .btn--filled').click();
        await expect(page.locator('li.recovery-code')).toHaveCount(10);

        // The Done button is gated behind the acknowledgement checkbox.
        const done = page.locator('.dialog__actions .btn--filled');
        await expect(done).toBeDisabled();
        await page.locator('.checkbox-row input[type="checkbox"]').check();
        await expect(done).toBeEnabled();
        await done.click();

        // Status refreshes to enabled.
        await expect(page.locator('[data-totp-status]')).toContainText('Enabled');
        await expect(page.locator('[data-action="totp-disable"]')).toBeVisible();
    });

    test('disables 2FA with master password + a current code', async ({ mockedPage: page, isMobile }) => {
        await openSettings(page, { enabled: true, remaining: 8 }, isMobile);
        await expect(page.locator('[data-totp-status]')).toContainText('Enabled');

        await page.locator('[data-action="totp-disable"]').click();
        await page.fill('#disable-pw', 'Master-Password-123');
        await page.fill('#disable-code', '123456');
        await page.locator('.dialog__actions .btn--danger').click();

        await expect(page.locator('[data-totp-status]')).toContainText('Disabled');
        await expect(page.locator('[data-action="totp-enable"]')).toBeVisible();
    });

    test('changes authenticator (re-auth, new QR, confirm)', async ({ mockedPage: page, isMobile }) => {
        await openSettings(page, { enabled: true, remaining: 8 }, isMobile);

        await page.locator('[data-action="totp-change"]').click();
        await expect(page.locator('.dialog')).toBeVisible();

        // Re-auth, then start enrollment → new QR.
        await page.fill('#totp-reauth-pw', 'Master-Password-123');
        await page.fill('#totp-reauth-code', '123456');
        await page.locator('.dialog__actions .btn--filled').click();
        await expect(page.locator('img.totp-qr')).toBeVisible();

        // Confirm the new authenticator (a change keeps existing recovery codes).
        await page.fill('#totp-verify', '654321');
        await page.locator('.dialog__actions .btn--filled').click();
        await expect(page.locator('[data-totp-status]')).toContainText('Enabled');
    });

    test('regenerates recovery codes', async ({ mockedPage: page, isMobile }) => {
        await openSettings(page, { enabled: true, remaining: 2 }, isMobile);

        await page.locator('[data-action="totp-regenerate"]').click();
        await page.fill('#regen-pw', 'Master-Password-123');
        await page.locator('.dialog__actions .btn--filled').click();
        await expect(page.locator('li.recovery-code')).toHaveCount(10);
    });
});
