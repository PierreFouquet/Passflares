// Vitest config for Stryker runs only (#89 §2).
//
// Same setup as vitest.config.mts, minus the things that make no sense under a
// mutation runner: coverage (Stryker re-runs the suite hundreds of times, and
// the v8 instrumentation would multiply an already long run by ~5) and the
// frontend suite (Stryker mutates src/, so only tests/backend can kill anything
// — running happy-dom tests per mutant would be pure cost).
import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
    test: {
        include: ['tests/backend/**/*.test.ts'],
        environment: 'node',
        setupFiles: ['tests/setup/localstorage-node26.ts'],
        globals: false,
        alias: {
            'cloudflare:workers': resolve(import.meta.dirname, 'tests/mocks/cloudflare-workers.ts')
        }
    },
    resolve: {
        extensions: ['.ts', '.js']
    }
});
