// Static-analysis guardrails for the worker code. These tests don't exercise
// behaviour — they grep the source for risky patterns that the static review
// done during the 1.0.1 release ruled out, so a future change re-introducing
// any of them fails CI instead of shipping silently.
//
// If one of these tests fires unexpectedly, look at the change that triggered
// it before relaxing the rule — the rules encode threat-model assumptions, not
// stylistic preferences.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const srcRoot = resolve(repoRoot, 'src');

function listSourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        const st = statSync(full);
        if (st.isDirectory()) out.push(...listSourceFiles(full));
        else if (/\.ts$/.test(entry)) out.push(full);
    }
    return out;
}

const sourceFiles = listSourceFiles(srcRoot);

describe('worker code security invariants', () => {
    it('finds at least one source file (sanity)', () => {
        expect(sourceFiles.length).toBeGreaterThan(3);
    });

    it('uses no eval() or new Function() in worker code', () => {
        const offenders: string[] = [];
        for (const f of sourceFiles) {
            const content = readFileSync(f, 'utf8');
            // Strip comments and string literals before matching so a doc
            // comment that mentions eval() doesn't trip the check.
            const stripped = content
                .replace(/\/\*[\s\S]*?\*\//g, '')
                .replace(/\/\/.*$/gm, '')
                .replace(/(['"`])(?:\\.|(?!\1).)*\1/g, '""');
            if (/\beval\s*\(/.test(stripped)) offenders.push(`${f}: eval(`);
            if (/\bnew\s+Function\s*\(/.test(stripped)) offenders.push(`${f}: new Function(`);
        }
        expect(offenders, offenders.join('\n')).toEqual([]);
    });

    it('every DB.prepare() call uses a static string (no template literals or +)', () => {
        // D1 .prepare() takes a SQL string; .bind() supplies params. A template
        // literal or concatenation in the .prepare() argument means a value was
        // interpolated into SQL — that's SQL injection.
        const offenders: string[] = [];
        const re = /\.prepare\s*\(\s*([^)]*?)\)/g;
        for (const f of sourceFiles) {
            const content = readFileSync(f, 'utf8');
            let m: RegExpExecArray | null;
            while ((m = re.exec(content)) !== null) {
                const arg = m[1];
                // A template literal containing ${ is dynamic. A `+` outside of
                // string boundaries is concatenation. Plain `'…' + '…'` (string
                // joining for line continuation) is also flagged — we want
                // every prepare call to take a single literal.
                const hasInterpolation = /`[^`]*\$\{/.test(arg);
                const hasConcat = /['"`]\s*\+|\+\s*['"`]/.test(arg);
                if (hasInterpolation || hasConcat) {
                    offenders.push(`${f}: ${arg.trim().slice(0, 80)}`);
                }
            }
        }
        expect(offenders, offenders.join('\n')).toEqual([]);
    });

    // GHSA-jrh6-9qp8-rfgf — non-constant-time comparison of password/secret
    // hashes. `===` on a hash short-circuits at the first differing byte. The
    // fix was timingSafeEqualHex; this stops it being undone by a refactor.
    it('never compares a stored hash with === or !==', () => {
        const offenders: string[] = [];
        // Any comparison operator with a *_hash identifier on either side.
        const re = /([A-Za-z_$][\w$.]*)\s*(===|!==|==|!=)\s*([A-Za-z_$][\w$.]*)/g;
        for (const f of sourceFiles) {
            const content = readFileSync(f, 'utf8');
            const stripped = content
                .replace(/\/\*[\s\S]*?\*\//g, '')
                .replace(/\/\/.*$/gm, '');
            let m: RegExpExecArray | null;
            while ((m = re.exec(stripped)) !== null) {
                const [, left, op, right] = m;
                const touchesHash = (id: string) => /(^|\.)(password_hash|code_hash)$/.test(id) ||
                    /^(verifiedHash|verifiedOldHash|storedHash)$/.test(id);
                if (touchesHash(left) || touchesHash(right)) {
                    offenders.push(`${f}: ${left} ${op} ${right}`);
                }
            }
        }
        expect(
            offenders,
            `Use timingSafeEqualHex (GHSA-jrh6-9qp8-rfgf):\n${offenders.join('\n')}`
        ).toEqual([]);
    });

    // GHSA-vp89-22wm-gjr8 — the brute-force limiter must not go back to KV.
    // A KV counter cannot be atomic: the read and write are separate operations
    // and reads are eventually consistent, so concurrent requests all observe
    // the same pre-increment value.
    it('implements rate limiting with the Durable Object, never a KV counter', () => {
        const offenders: string[] = [];
        for (const f of sourceFiles) {
            const content = readFileSync(f, 'utf8');
            const stripped = content
                .replace(/\/\*[\s\S]*?\*\//g, '')
                .replace(/\/\/.*$/gm, '');
            // The old binding, and any KV namespace used for limiting.
            if (/\benv\.RATE_LIMIT\b(?!ER)/.test(stripped)) {
                offenders.push(`${f}: env.RATE_LIMIT (KV) — use env.RATE_LIMITER (Durable Object)`);
            }
            if (/RATE_LIMIT\s*:\s*KVNamespace/.test(stripped)) {
                offenders.push(`${f}: Env declares a KV rate limiter`);
            }
        }
        expect(offenders, offenders.join('\n')).toEqual([]);
    });

    // The limiter's read-modify-write is only safe because it happens inside a
    // single Durable Object method, where workerd's input gate serialises it.
    // Splitting it across the Worker — read the count here, write it back there
    // — reintroduces the race regardless of the storage backend.
    it('mutates the limiter only through the Durable Object stub', () => {
        const limiterSource = readFileSync(resolve(srcRoot, 'rateLimiter.ts'), 'utf8');
        // The class must own every write. If a helper outside the class ever
        // calls storage.put directly, the gate no longer covers the sequence.
        const classBody = limiterSource.slice(limiterSource.indexOf('export class RateLimiter'));
        const helperBody = limiterSource.slice(0, limiterSource.indexOf('export class RateLimiter'));
        expect(helperBody).not.toMatch(/storage\.(put|delete|deleteAll)/);
        expect(classBody).toMatch(/storage\.put/);
    });

    // #73 — audit writes were floating promises. logAudit now returns void and
    // registers its own write with ctx.waitUntil, so there is nothing to await;
    // `await logAudit(` means someone made it thenable again.
    it('never awaits logAudit — it must be fire-and-forget via ctx.waitUntil', () => {
        const offenders: string[] = [];
        for (const f of sourceFiles) {
            const content = readFileSync(f, 'utf8');
            if (/await\s+logAudit\s*\(/.test(content)) offenders.push(`${f}: await logAudit(`);
        }
        expect(offenders, offenders.join('\n')).toEqual([]);
    });

    it('registers the audit write with ctx.waitUntil', () => {
        const auditSource = readFileSync(resolve(srcRoot, 'auditLog.ts'), 'utf8');
        expect(auditSource).toMatch(/ctx\.waitUntil\s*\(/);
        // An `async function logAudit` returning a promise nobody awaits is the
        // original defect; the signature itself is the guard.
        expect(auditSource).not.toMatch(/export\s+async\s+function\s+logAudit/);
    });

    it('writes audit_logs only from auditLog.ts', () => {
        const offenders: string[] = [];
        for (const f of sourceFiles) {
            if (/auditLog\.ts$/.test(f)) continue;
            const content = readFileSync(f, 'utf8');
            if (/INSERT\s+INTO\s+audit_logs/i.test(content)) {
                offenders.push(`${f}: direct audit_logs INSERT — call logAudit() instead`);
            }
        }
        expect(offenders, offenders.join('\n')).toEqual([]);
    });

    // #73 "Also" — exception text is persisted for the whole retention window
    // and can carry internal detail. The full error still reaches the
    // observability logs via console.error; only the durable copy is a code.
    it('never persists a raw error.message in an audit payload', () => {
        const offenders: string[] = [];
        for (const f of sourceFiles) {
            const content = readFileSync(f, 'utf8');
            if (/error:\s*\w+\.message/.test(content)) {
                offenders.push(`${f}: error.message in an audit payload — use auditErrorCode()`);
            }
        }
        expect(offenders, offenders.join('\n')).toEqual([]);
    });

    // #78 — a bare `await request.json()` throws on a malformed body, escapes
    // the handler and surfaces as 500 "Service unavailable" for what is a
    // client error. safeJson() returns null instead so handlers can answer 400.
    it('parses request bodies through safeJson, never a bare request.json()', () => {
        const offenders: string[] = [];
        for (const f of sourceFiles) {
            // utils.ts defines safeJson; totp.ts has its own guarded wrapper.
            if (/(utils|totp)\.ts$/.test(f)) continue;
            const content = readFileSync(f, 'utf8');
            const stripped = content
                .replace(/\/\*[\s\S]*?\*\//g, '')
                .replace(/\/\/.*$/gm, '');
            const re = /await\s+request\.json\s*\(/g;
            let m: RegExpExecArray | null;
            while ((m = re.exec(stripped)) !== null) {
                offenders.push(`${f}: await request.json() — use safeJson(request)`);
            }
        }
        expect(offenders, offenders.join('\n')).toEqual([]);
    });

    it('does not call fetch() with a user-controlled URL', () => {
        // Every fetch() in worker code should target either a hardcoded URL
        // constant or a built-in binding (env.ASSETS.fetch(request)). A call
        // like fetch(req.body.url) would be SSRF.
        const offenders: string[] = [];
        for (const f of sourceFiles) {
            const content = readFileSync(f, 'utf8');
            // Match `fetch(` not preceded by env.ASSETS. or .
            const re = /(?<![\w.])fetch\s*\(\s*([^,)]+)/g;
            let m: RegExpExecArray | null;
            while ((m = re.exec(content)) !== null) {
                const arg = m[1].trim();
                // Allowed forms: an ALL_CAPS constant, a string literal, or
                // `request` (used by env.ASSETS.fetch — but env.ASSETS.fetch
                // is matched by the lookbehind anyway).
                const isConstant = /^[A-Z_][A-Z0-9_]*$/.test(arg);
                const isStringLiteral = /^['"`]/.test(arg);
                // The worker exports `async fetch(request: Request, ...)` as
                // its handler — a method definition, not a call. Parameter
                // lists have TypeScript type annotations (`name: Type`), which
                // real call sites don't.
                const isMethodDefinition = /^\w+\s*:\s*[A-Z]/.test(arg);
                if (!isConstant && !isStringLiteral && !isMethodDefinition) {
                    offenders.push(`${f}: fetch(${arg.slice(0, 60)})`);
                }
            }
        }
        expect(offenders, offenders.join('\n')).toEqual([]);
    });
});
