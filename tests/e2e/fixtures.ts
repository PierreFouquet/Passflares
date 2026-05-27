import { test as base, expect, type Page } from '@playwright/test';

/**
 * API mocks for E2E tests. Each test starts in a clean state: no JWT in
 * localStorage, no cached prefs. Helpers below seed login state + mock the
 * REST endpoints.
 */

type Prefs = { theme: string; density: string; shape: string; accent: string };

const DEFAULT_PREFS: Prefs = { theme: 'system', density: 'comfortable', shape: 'rounded', accent: 'emerald' };

export interface MockServer {
    prefs: Prefs;
    vaults: any[];
    organizations: any[];
    members: Record<number, any[]>;
}

export const test = base.extend<{
    server: MockServer;
    mockedPage: Page;
}>({
    server: async ({}, use) => {
        const server: MockServer = {
            prefs: { ...DEFAULT_PREFS },
            vaults: [],
            organizations: [],
            members: {}
        };
        await use(server);
    },

    mockedPage: async ({ page, server }, use) => {
        await page.route('**/api/**', async (route) => {
            const req = route.request();
            const url = new URL(req.url());
            const path = url.pathname;
            const method = req.method();

            // ----- POST /api/register -----
            if (path === '/api/register' && method === 'POST') {
                return route.fulfill({ status: 201, contentType: 'application/json',
                    body: JSON.stringify({ message: 'Registered.' }) });
            }
            // ----- POST /api/login -----
            if (path === '/api/login' && method === 'POST') {
                return route.fulfill({ status: 200, contentType: 'application/json',
                    body: JSON.stringify({
                        userId: 1, email: 'tester@example.com',
                        encryptionSalt: 'aabbccddeeff00112233445566778899',
                        token: 'fake-test-jwt'
                    })});
            }
            // ----- GET /api/users/me/preferences -----
            if (path === '/api/users/me/preferences' && method === 'GET') {
                return route.fulfill({ status: 200, contentType: 'application/json',
                    body: JSON.stringify({ user_id: 1, ...server.prefs, updated_at: 'now' })});
            }
            // ----- PUT /api/users/me/preferences -----
            if (path === '/api/users/me/preferences' && method === 'PUT') {
                const body = req.postDataJSON?.() ?? JSON.parse(req.postData() || '{}');
                Object.assign(server.prefs, body);
                return route.fulfill({ status: 200, contentType: 'application/json',
                    body: JSON.stringify({ user_id: 1, ...server.prefs, updated_at: 'now' })});
            }
            // ----- GET /api/vaults -----
            if (path === '/api/vaults' && method === 'GET') {
                return route.fulfill({ status: 200, contentType: 'application/json',
                    body: JSON.stringify(server.vaults) });
            }
            // ----- POST /api/vaults -----
            if (path === '/api/vaults' && method === 'POST') {
                const body = JSON.parse(req.postData() || '{}');
                const id = server.vaults.length + 1;
                const newVault = {
                    id, name: body.name, description: body.description ?? '',
                    owner_id: body.ownerId, owner_type: body.ownerType,
                    permission_level: body.initialPermissionLevel ?? 'manage',
                    r2_object_key: `r2_${id}`, current_key_version: 'v1'
                };
                server.vaults.push(newVault);
                return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(newVault) });
            }
            // ----- PUT /api/vaults/:id/data (encrypted upload) -----
            if (path.match(/^\/api\/vaults\/\d+\/data$/) && method === 'PUT') {
                return route.fulfill({ status: 204 });
            }
            // ----- GET /api/vaults/:id/data -----
            if (path.match(/^\/api\/vaults\/\d+\/data$/) && method === 'GET') {
                // Empty vault (no encrypted data yet)
                return route.fulfill({ status: 200, contentType: 'application/json', body: 'null' });
            }
            // ----- GET /api/organizations -----
            if (path === '/api/organizations' && method === 'GET') {
                return route.fulfill({ status: 200, contentType: 'application/json',
                    body: JSON.stringify(server.organizations) });
            }
            // ----- POST /api/organizations -----
            if (path === '/api/organizations' && method === 'POST') {
                const body = JSON.parse(req.postData() || '{}');
                const id = server.organizations.length + 1;
                const org = { id, name: body.name, description: body.description ?? '', created_by: 1, created_at: 'now' };
                server.organizations.push(org);
                server.members[id] = [{ userId: 1, email: 'tester@example.com', role: 'super_admin' }];
                return route.fulfill({ status: 201, contentType: 'application/json', body: JSON.stringify(org) });
            }
            // ----- GET /api/organizations/:id/members -----
            const memberMatch = path.match(/^\/api\/organizations\/(\d+)\/members$/);
            if (memberMatch && method === 'GET') {
                const id = Number(memberMatch[1]);
                return route.fulfill({ status: 200, contentType: 'application/json',
                    body: JSON.stringify(server.members[id] ?? []) });
            }

            // Fallback — return 200 with empty body to avoid hanging the test
            return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
        });
        await use(page);
    }
});

export { expect };

export async function gotoAndSeedLogin(page: Page) {
    // Pre-seed before boot() runs. Two things have to be true for boot to
    // land on the signed-in path:
    //   1. localStorage has jwtToken + userInfo  → isLoggedIn() = true
    //   2. state.encryptionKey is non-null       → hasKey()    = true
    //
    // (2) is the catch: in production the key is a real CryptoKey derived
    // from the master password at sign-in and only lives in memory. Tests
    // can't reproduce that without doing a full PBKDF2 derive every run,
    // so main.js exposes a tiny window-flag test seam (search the source
    // for `__PASSFLARES_E2E_FAKE_KEY`). addInitScript runs in every frame
    // before the page's own scripts, so the flag is set by the time
    // boot()'s DOMContentLoaded listener fires.
    await page.addInitScript(() => {
        window.localStorage.setItem('jwtToken', 'fake-test-jwt');
        window.localStorage.setItem('userInfo', JSON.stringify({
            userId: 1, email: 'tester@example.com',
            encryptionSalt: 'aabbccddeeff00112233445566778899'
        }));
        // Any truthy non-null value satisfies hasKey() in state.js.
        // Tests that exercise actual encrypt/decrypt would need a real
        // CryptoKey — for those, do a real login through the auth flow
        // instead of using this fixture.
        (window as unknown as { __PASSFLARES_E2E_FAKE_KEY: unknown }).__PASSFLARES_E2E_FAKE_KEY = { __test: true };
    });
    await page.goto('/');
}
