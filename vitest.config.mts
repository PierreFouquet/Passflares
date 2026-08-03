// .mts + import.meta.dirname, not .ts + __dirname: Vite's forthcoming native
// config loader treats the config as real ESM, where CommonJS globals do not
// exist. Both would warn today and break on that release.
import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
    test: {
        include: ['tests/**/*.test.{ts,js}'],
        // Default environment for backend tests
        environment: 'node',
        // Override per-file with: // @vitest-environment happy-dom
        environmentOptions: {
            happyDOM: { width: 1280, height: 720 }
        },
        globals: false,
        // Allow resolving .js imports to .ts source files
        alias: {
            // `cloudflare:workers` is a workerd built-in with no Node
            // resolution. src/rateLimiter.ts imports DurableObject from it, so
            // without this every test that reaches worker.ts fails to load.
            'cloudflare:workers': resolve(import.meta.dirname, 'tests/mocks/cloudflare-workers.ts')
        }
    },
    resolve: {
        extensions: ['.ts', '.js']
    }
});
