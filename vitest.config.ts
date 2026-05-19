import { defineConfig } from 'vitest/config';

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
            // vitest resolves these automatically via esbuild
        }
    },
    resolve: {
        extensions: ['.ts', '.js']
    }
});
