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
