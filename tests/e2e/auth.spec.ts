import { test, expect } from './fixtures';

test.describe('Auth screen', () => {
    test('renders centered card with brand mark and tabs', async ({ mockedPage: page }) => {
        await page.goto('/');
        await expect(page.locator('.auth-screen')).toBeVisible();
        await expect(page.locator('.auth-card h2')).toContainText('Access your vault');
        await expect(page.locator('.auth-tabs button[data-tab="login"]')).toBeVisible();
        await expect(page.locator('.auth-tabs button[data-tab="register"]')).toBeVisible();
    });

    test('switches tabs between sign-in and create-account', async ({ mockedPage: page }) => {
        await page.goto('/');
        await expect(page.locator('#login-form')).toBeVisible();
        await expect(page.locator('#register-form')).toBeHidden();

        await page.locator('.auth-tabs button[data-tab="register"]').click();
        await expect(page.locator('#register-form')).toBeVisible();
        await expect(page.locator('#login-form')).toBeHidden();
    });

    test('password show/hide toggle reveals the field', async ({ mockedPage: page }) => {
        await page.goto('/');
        const pwd = page.locator('#login-master-password');
        await pwd.fill('Secret123!');
        await expect(pwd).toHaveAttribute('type', 'password');
        await page.locator('#login-form [data-toggle-password]').click();
        await expect(pwd).toHaveAttribute('type', 'text');
    });

    test('password strength meter updates as the user types', async ({ mockedPage: page }) => {
        await page.goto('/');
        await page.locator('.auth-tabs button[data-tab="register"]').click();
        const pwd = page.locator('#register-master-password');
        await pwd.fill('weak');
        await expect(page.locator('.password-meter')).toHaveAttribute('data-score', /[0-1]/);
        await pwd.fill('AStrongPassword!1234');
        await expect(page.locator('.password-meter')).toHaveAttribute('data-score', /[3-4]/);
    });
});
