import { defineConfig, devices } from '@playwright/test';

/**
 * E2E test config.
 *
 * Tests run against the static frontend served from `public/`. API calls are
 * intercepted per-test with `page.route('**\/api/**', …)` so we don't need
 * `wrangler dev` running. This keeps E2E hermetic and fast.
 *
 * To run against a live worker, set `PASSFLARES_BASE_URL` and Playwright will
 * skip the local web server.
 */

const PORT = Number(process.env.PASSFLARES_PORT ?? 4173);
const BASE = process.env.PASSFLARES_BASE_URL ?? `http://localhost:${PORT}`;

export default defineConfig({
    testDir: './tests/e2e',
    fullyParallel: true,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: process.env.CI ? 1 : undefined,
    reporter: process.env.CI ? [['github'], ['list']] : 'list',

    use: {
        baseURL: BASE,
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure'
    },

    projects: [
        {
            name: 'chromium-desktop',
            use: { ...devices['Desktop Chrome'] }
        },
        {
            // Chromium with Pixel 7 emulation. Avoids the WebKit system-deps
            // requirement (libavif16) that fails on some Linux distros without
            // sudo. Swap to `devices['iPhone 14']` (and add `webkit` install)
            // for a real WebKit run in CI.
            name: 'chromium-mobile',
            use: { ...devices['Pixel 7'] }
        }
    ],

    webServer: process.env.PASSFLARES_BASE_URL ? undefined : {
        command: `npx http-server public -p ${PORT} -c-1 --silent`,
        port: PORT,
        reuseExistingServer: !process.env.CI,
        stdout: 'pipe',
        stderr: 'pipe'
    }
});
