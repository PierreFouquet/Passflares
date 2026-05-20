import { test, expect, gotoAndSeedLogin } from './fixtures';

test.describe('Dashboard', () => {
    test('lands on Dashboard after sign in', async ({ mockedPage: page }) => {
        await gotoAndSeedLogin(page);
        await expect(page.locator('.dash-hero h1')).toContainText('Welcome back');
        await expect(page.locator('.dash-section h2', { hasText: 'Security overview' })).toBeVisible();
        await expect(page.locator('.dash-section h2', { hasText: 'Recent vaults' })).toBeVisible();
    });

    test('shows empty state when no vaults exist', async ({ mockedPage: page }) => {
        await gotoAndSeedLogin(page);
        await expect(page.locator('[data-recent-vaults] .empty-state')).toBeVisible();
        await expect(page.locator('[data-recent-vaults]')).toContainText('No vaults yet');
    });

    test('renders security tiles', async ({ mockedPage: page }) => {
        await gotoAndSeedLogin(page);
        const tiles = page.locator('[data-security-tiles] .tile');
        await expect(tiles).toHaveCount(4);
    });
});

test.describe('Navigation between pages', () => {
    test('clicks through all nav rail items', async ({ mockedPage: page, isMobile }) => {
        await gotoAndSeedLogin(page);

        const sections = [
            { nav: 'vaults',        text: 'Vaults' },
            { nav: 'organisations', text: 'Organisations' },
            { nav: 'settings',      text: 'Settings' },
            { nav: 'home',          text: 'Welcome back' }
        ];

        for (const s of sections) {
            if (isMobile) await page.locator('#hamburger-btn').click();
            await page.locator(`.nav-rail__item[data-nav="${s.nav}"]`).click();
            await expect(page.locator('.app-main')).toContainText(s.text);
        }
    });
});

test.describe('Global search palette', () => {
    test('opens on Ctrl/Cmd+K', async ({ mockedPage: page }) => {
        await gotoAndSeedLogin(page);
        // Wait for the app shell to be fully initialised before sending keys
        await expect(page.locator('#global-search')).toBeVisible();
        await page.locator('body').click();  // ensure focus is on body, not in search
        await page.keyboard.press('Control+K');
        await expect(page.locator('.palette')).toBeVisible();
    });

    test('closes on Escape', async ({ mockedPage: page }) => {
        await gotoAndSeedLogin(page);
        await expect(page.locator('#global-search')).toBeVisible();
        await page.locator('body').click();
        await page.keyboard.press('Control+K');
        await expect(page.locator('.palette')).toBeVisible();
        await page.keyboard.press('Escape');
        await expect(page.locator('.palette')).not.toBeVisible();
    });
});
