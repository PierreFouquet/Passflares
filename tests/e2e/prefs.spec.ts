import { test, expect, gotoAndSeedLogin } from './fixtures';
import type { Page } from '@playwright/test';

// Helper: select a value in a .toggle-group by clicking the visible label/chip.
// The radio inputs are visually hidden so .check() fails on touch viewports —
// clicking the label (which natively toggles the radio) works everywhere.
async function selectToggle(page: Page, group: string, value: string) {
    await page.locator(`[data-pref-group="${group}"] input[value="${value}"]`).evaluate((el: HTMLInputElement) => {
        el.click();
        el.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await page.waitForTimeout(50);
}

test.describe('Preferences (Settings page)', () => {
    test('navigates to Settings via nav rail', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();
        await expect(page.locator('.page-header h1')).toContainText('Settings');
    });

    test('changes theme to light and updates <html data-theme>', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();

        await selectToggle(page, 'theme', 'light');
        await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    });

    test('changes density to compact and updates <html data-density>', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();

        await selectToggle(page, 'density', 'compact');
        await expect(page.locator('html')).toHaveAttribute('data-density', 'compact');
    });

    test('changes shape to pill and updates <html data-shape>', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();

        await selectToggle(page, 'shape', 'pill');
        await expect(page.locator('html')).toHaveAttribute('data-shape', 'pill');
    });

    test('changes accent to purple and updates <html data-accent>', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();

        await page.locator('[data-pref-group="accent"] [data-accent-value="purple"]').click();
        await expect(page.locator('html')).toHaveAttribute('data-accent', 'purple');
    });

    test('shape change actually mutates --radius-card live (CSS variable)', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();

        const radiusBefore = await page.evaluate(() =>
            getComputedStyle(document.documentElement).getPropertyValue('--radius-card').trim()
        );
        await selectToggle(page, 'shape', 'sharp');
        const radiusAfter = await page.evaluate(() =>
            getComputedStyle(document.documentElement).getPropertyValue('--radius-card').trim()
        );
        expect(radiusAfter).not.toBe(radiusBefore);
    });

    test('theme toggle button in app bar cycles dark → light → system', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);
        // Set to 'dark' via the Settings page so internal prefs state is in sync
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();
        await selectToggle(page, 'theme', 'dark');
        await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');

        // Go back to home so the app bar button is visible without obstructing
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="home"]').click();

        await page.locator('#theme-toggle-btn').click();
        await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
        await page.locator('#theme-toggle-btn').click();
        await expect(page.locator('html')).toHaveAttribute('data-theme', 'system');
    });

    test('preference change persists across reload', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);
        if (isMobile) await page.locator('#hamburger-btn').click();
        await page.locator('.nav-rail__item[data-nav="settings"]').click();
        await selectToggle(page, 'density', 'spacious');
        await expect(page.locator('html')).toHaveAttribute('data-density', 'spacious');

        await page.waitForTimeout(500);  // let debounced PUT fire
        await page.reload();
        await expect(page.locator('html')).toHaveAttribute('data-density', 'spacious');
    });
});
