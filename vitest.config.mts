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
        // Runs after the environment is built, per test file. Node 26 defines a
        // global `localStorage` accessor that shadows happy-dom's and returns
        // undefined without `--localstorage-file`; this takes it back. See the
        // file for why `--localstorage-file` is the wrong fix.
        setupFiles: ['tests/setup/localstorage-node26.ts'],
        globals: false,
        // Coverage floor (#89 §4, #83 §E). Necessary, not sufficient: it stops a
        // new handler shipping with *zero* behavioural coverage, which is the
        // failure it is for. It says nothing about whether the lines it counts
        // are covered by tests that can actually fail — that is the
        // falsifiability gate's job (scripts/mutation-check.mjs), and the two
        // are deliberately separate signals.
        //
        // Run with `npm run test:coverage`, which raises the per-test timeout:
        // v8 instrumentation slows the real-scrypt and real-Argon2id paths by
        // roughly 5x, and those tests are the ones worth keeping in the count.
        coverage: {
            provider: 'v8',
            // Both halves of the product. Covering only src/ was the original
            // bias (#89 §1) — the zero-knowledge guarantee lives in public/js/.
            include: ['src/**/*.ts', 'public/js/**/*.js'],
            // Only vendored upstream is excluded, and only because it is
            // guarded byte-for-byte by tests/backend/vendor-integrity.test.ts
            // instead. Nothing else is carved out to flatter the number: the
            // page controllers are mostly Playwright's territory and drag the
            // figure down, but auth.js and vaults.js reach into the key
            // hierarchy, so excluding them would hide exactly the wrong lines.
            // The blended figure is therefore low by design — which is why the
            // floors below are per-area rather than one global number.
            exclude: ['public/vendor/**'],
            reporter: ['text-summary', 'json-summary'],
            reportsDirectory: './coverage',
            // Floors, not targets. Each sits just under what the suite achieves
            // today, so an uncovered addition trips it while ordinary churn does
            // not. Raise them when the real figure rises; never lower one to
            // turn a red build green — that is the one move that makes this
            // whole mechanism worthless.
            // Measured 2026-08-10 at 677 tests:
            //   src/**            84.5 st / 85.4 br / 95.9 fn / 85.0 ln
            //   key hierarchy     91.5 / 72.4 / 94.0 / 92.4
            //   public/js/** all  42.4 / 38.2 / 44.6 / 44.3
            thresholds: {
                'src/**/*.ts': { statements: 80, branches: 80, functions: 90, lines: 80 },
                // The key hierarchy. Tight, because these four files are the
                // zero-knowledge guarantee and nothing else in the repo is.
                'public/js/{auth-flow,crypto,keys,vault-keys}.js':
                    { statements: 88, branches: 68, functions: 90, lines: 88 },
                // Everything else in the browser bundle, app shell included.
                // Low because the page controllers are covered by Playwright,
                // which contributes nothing here — a floor that stops them
                // rotting away entirely, not a claim that they are tested.
                'public/js/**/*.js': { statements: 38, branches: 34, functions: 40, lines: 40 }
            }
        },
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
