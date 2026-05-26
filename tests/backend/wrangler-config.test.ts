// Regression guard for the 1.0.2 fix.
//
// Cloudflare Workers' [assets] binding defaults to `run_worker_first = false`,
// which silently bypasses the Worker for any request that matches a static
// asset. That bypass is exactly what made 1.0.1's security-header layer
// invisible to external scanners against `/` and `/js/*.js`. If anyone ever
// removes `run_worker_first = true` from wrangler.toml, this test fails
// before it reaches production.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function readAssetsBlock(path: string): string {
    const text = readFileSync(resolve(path), 'utf8');
    // The [assets] block runs until the next top-level [section] header
    // (or the end of file). This regex is intentionally loose — we don't
    // need a real TOML parser to assert one boolean.
    const match = text.match(/^\[assets\]([\s\S]*?)(?=^\[|\Z)/m);
    expect(match, `[assets] block not found in ${path}`).toBeTruthy();
    return match![1];
}

describe('wrangler.toml — [assets] binding', () => {
    it('sets run_worker_first = true (so the Worker runs for static assets)', () => {
        const block = readAssetsBlock('wrangler.toml');
        expect(block).toMatch(/^\s*run_worker_first\s*=\s*true\s*$/m);
    });

    it('does NOT explicitly disable run_worker_first', () => {
        // Catches a regression where someone flips the value to false.
        const block = readAssetsBlock('wrangler.toml');
        expect(block).not.toMatch(/^\s*run_worker_first\s*=\s*false\s*$/m);
    });
});

describe('wrangler.toml.example — [assets] binding', () => {
    it('also sets run_worker_first = true so forks inherit the fix', () => {
        const block = readAssetsBlock('wrangler.toml.example');
        expect(block).toMatch(/^\s*run_worker_first\s*=\s*true\s*$/m);
    });
});
