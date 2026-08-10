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

// The atomic brute-force limiter is a Durable Object. Without the binding *and*
// the class migration, `env.RATE_LIMITER` is undefined at runtime and every
// login throws — so a config regression here takes the site down rather than
// silently weakening the limit. Both must be present in both files.
describe.each(['wrangler.toml', 'wrangler.toml.example'])('%s — rate limiter', (path) => {
    const text = () => readFileSync(resolve(path), 'utf8');

    it('binds RATE_LIMITER to the RateLimiter class', () => {
        expect(text()).toMatch(/\[\[durable_objects\.bindings\]\][\s\S]*?name\s*=\s*"RATE_LIMITER"/);
        expect(text()).toMatch(/class_name\s*=\s*"RateLimiter"/);
    });

    it('declares the class with a SQLite-backed migration', () => {
        // new_classes (key-value backed) can no longer be created on accounts
        // without an existing KV-backed namespace, and the Workers Free plan has
        // only ever supported the SQLite backend.
        expect(text()).toMatch(/new_sqlite_classes\s*=\s*\[\s*"RateLimiter"\s*\]/);
        expect(text()).not.toMatch(/new_classes\s*=\s*\[\s*"RateLimiter"\s*\]/);
    });

    it('no longer binds the KV namespace the limiter used to use', () => {
        expect(text()).not.toMatch(/binding\s*=\s*"RATE_LIMIT"\s*$/m);
    });

    it('schedules the audit-log retention sweep', () => {
        // Without a cron trigger the scheduled() handler never runs and
        // audit_logs grows without bound (#73).
        expect(text()).toMatch(/\[triggers\][\s\S]*?crons\s*=\s*\[/);
    });
});

// compatibility_date and compatibility_flags decide which runtime APIs the
// Worker gets — Request/Response semantics, stream behaviour, which Node
// built-ins exist. Editing either changes production behaviour with no code
// diff to review, and nothing noticed the last move (2026-05-26 -> 2026-08-07,
// #89 §7).
//
// So the value is pinned here rather than merely "present". Bumping it is fine
// and sometimes necessary — but it now costs a deliberate edit to this file,
// which is where the reviewer gets told what they are agreeing to. Before
// changing COMPATIBILITY_DATE, read the runtime changes between the two dates
// (https://developers.cloudflare.com/workers/configuration/compatibility-dates/)
// and check the installed wrangler/workerd actually supports the new one — a
// date past the runtime's ceiling makes `wrangler dev` refuse to boot.
const COMPATIBILITY_DATE = '2026-08-07';

// nodejs_compat is load-bearing: src/ reaches for Node built-ins (jsonwebtoken
// pulls in crypto/buffer/stream), so dropping the flag breaks the Worker at
// import time, before any handler runs.
const COMPATIBILITY_FLAGS = ['nodejs_compat'];

describe.each(['wrangler.toml', 'wrangler.toml.example'])('%s — runtime contract', (path) => {
    const text = () => readFileSync(resolve(path), 'utf8');

    function compatibilityDate(): string | null {
        return text().match(/^compatibility_date\s*=\s*"([^"]+)"/m)?.[1] ?? null;
    }

    function compatibilityFlags(): string[] {
        const block = text().match(/^compatibility_flags\s*=\s*\[([^\]]*)\]/m)?.[1];
        if (block === undefined) return [];
        return [...block.matchAll(/"([^"]+)"/g)].map(m => m[1]);
    }

    it(`pins compatibility_date to ${COMPATIBILITY_DATE}`, () => {
        expect(compatibilityDate()).toBe(COMPATIBILITY_DATE);
    });

    it('declares compatibility_flags including nodejs_compat', () => {
        expect(compatibilityFlags()).toEqual(COMPATIBILITY_FLAGS);
    });

    it('uses a real ISO date, not a placeholder', () => {
        // A malformed date is silently ignored by some tooling, which then
        // falls back to the oldest possible semantics.
        const date = compatibilityDate();
        expect(date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(Number.isNaN(Date.parse(date!))).toBe(false);
    });
});

describe('wrangler.toml and wrangler.toml.example agree on the runtime', () => {
    // A fork deploying from the example gets a different runtime from the one
    // every test here ran against — which is the kind of divergence that only
    // shows up as "works upstream, breaks on my account".
    const read = (p: string) => readFileSync(resolve(p), 'utf8');

    it('declares the same compatibility_date in both files', () => {
        const live = read('wrangler.toml').match(/^compatibility_date\s*=\s*"([^"]+)"/m)?.[1];
        const example = read('wrangler.toml.example').match(/^compatibility_date\s*=\s*"([^"]+)"/m)?.[1];
        expect(example).toBe(live);
    });

    it('declares the same compatibility_flags in both files', () => {
        const flagsOf = (p: string) => read(p).match(/^compatibility_flags\s*=\s*\[([^\]]*)\]/m)?.[1]?.trim();
        expect(flagsOf('wrangler.toml.example')).toBe(flagsOf('wrangler.toml'));
    });
});
