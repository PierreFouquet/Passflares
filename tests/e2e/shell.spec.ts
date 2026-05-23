import { test, expect, gotoAndSeedLogin } from './fixtures';

test.describe('App shell (signed in)', () => {
    test('shows the nav rail with all sections on desktop', async ({ mockedPage: page, isMobile }) => {
        test.skip(!!isMobile, 'desktop only — mobile collapses rail to drawer');
        await gotoAndSeedLogin(page);
        await expect(page.locator('.nav-rail')).toBeVisible();
        const labels = await page.locator('.nav-rail__item .nav-rail__label').allTextContents();
        expect(labels).toEqual(expect.arrayContaining(['Home', 'Vaults', 'Orgs', 'Settings']));
    });

    test('app bar renders the brand wordmark, search, and user menu', async ({ mockedPage: page }) => {
        await gotoAndSeedLogin(page);
        await expect(page.locator('.app-bar__brand svg')).toBeVisible();
        await expect(page.locator('#global-search')).toBeVisible();
        await expect(page.locator('#user-menu-btn')).toBeVisible();
    });

    test('user menu opens and shows email + sign-out', async ({ mockedPage: page }) => {
        await gotoAndSeedLogin(page);
        await page.locator('#user-menu-btn').click();
        await expect(page.locator('#user-menu')).toBeVisible();
        await expect(page.locator('#user-menu-email')).toContainText('tester@example.com');
        await expect(page.locator('#logout-btn')).toBeVisible();
    });

    test('mobile hamburger opens the side drawer', async ({ mockedPage: page, isMobile }) => {
        test.skip(!isMobile, 'mobile only');
        await gotoAndSeedLogin(page);
        await page.locator('#hamburger-btn').click();
        await expect(page.locator('.nav-rail')).toHaveClass(/is-open/);
        await expect(page.locator('.nav-rail-scrim')).toHaveClass(/is-open/);
    });

    test('search shortcut hint is visible on desktop', async ({ mockedPage: page, isMobile }) => {
        test.skip(!!isMobile, 'desktop only — shortcuts are hidden on mobile by design');
        await gotoAndSeedLogin(page);
        await expect(page.locator('#search-shortcut-hint')).toBeVisible();
    });

    test('search shortcut hint is hidden on mobile', async ({ mockedPage: page, isMobile }) => {
        test.skip(!isMobile, 'mobile only');
        await gotoAndSeedLogin(page);
        await expect(page.locator('#search-shortcut-hint')).toBeHidden();
    });

    test('command palette keyboard-hint footer is hidden on mobile', async ({ mockedPage: page, isMobile }) => {
        test.skip(!isMobile, 'mobile only');
        await gotoAndSeedLogin(page);
        await page.locator('#global-search').click();
        await page.locator('#global-search').fill('a');
        await expect(page.locator('.palette')).toBeVisible();
        await expect(page.locator('.palette__hint')).toBeHidden();
    });
});
