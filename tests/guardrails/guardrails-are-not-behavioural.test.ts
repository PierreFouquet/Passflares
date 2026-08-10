// Keeps the guardrail/behavioural boundary real (#89 §5, #83 §3).
//
// The point of this directory is that nothing in it executes product code — so
// nobody can mistake its assertions for evidence that the product works. A
// boundary maintained by convention decays the first time someone adds "just
// one" handler call here, and then the separation is a lie that reads as truth.
// So the rule is asserted.
//
// The inverse rule matters too: a *behavioural* test that only greps source is
// the failure #83 §3 named, and moving one into tests/backend/ would hide it
// again. That direction is a judgement call and is not automated; this file
// only holds the line that guardrails stay inert.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

function guardrailFiles(): string[] {
    return readdirSync(here)
        .filter(f => f.endsWith('.test.ts') || f.endsWith('.test.js'))
        .map(f => join(here, f));
}

/**
 * Strips comments before scanning for imports.
 *
 * This file caught itself without it: the prose below mentions
 * `import('../../src/auth.js')` as an example of what to look for, and a raw
 * text scan cannot tell an example from an import. Only block comments and
 * whole-line `//` comments are removed — a trailing `//` is left alone so that
 * a `'https://…'` inside real code is not truncated into a false negative.
 */
function withoutComments(source: string): string {
    return source
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .split('\n')
        .filter(line => !/^\s*\/\//.test(line))
        .join('\n');
}

describe('tests/guardrails contains only source greps', () => {
    it('finds the guardrail files (a rename must not silently empty this suite)', () => {
        // Without this, deleting or renaming every file here would leave the
        // it.each blocks below iterating an empty list and passing vacuously —
        // which is precisely the failure mode this directory exists to name.
        const files = guardrailFiles();
        expect(files.length).toBeGreaterThanOrEqual(3);
        expect(files.map(f => f.split('/').pop())).toContain('code-security-invariants.test.ts');
        expect(files.map(f => f.split('/').pop())).toContain('static-security-audit.test.ts');
    });

    it.each(guardrailFiles().map(f => [f.split('/').pop()!, f]))(
        '%s imports no product code',
        (_name, file) => {
            const source = withoutComments(readFileSync(file, 'utf8'));
            const offending: string[] = [];

            for (const m of source.matchAll(/^\s*import\s[^;]*?from\s+['"]([^'"]+)['"]/gm)) {
                const spec = m[1];
                // Relative specifiers are the only way to reach product code
                // from here; bare ones are node: builtins and vitest.
                if (!spec.startsWith('.')) continue;
                const resolved = resolve(dirname(file), spec);
                if (resolved.includes('/src/') || resolved.includes('/public/')) {
                    offending.push(spec);
                }
            }

            expect(
                offending,
                `${_name} imports product code (${offending.join(', ')}). A test that ` +
                'executes src/ or public/js/ is a behavioural test and belongs in ' +
                'tests/backend/ or tests/frontend/, where its coverage is counted honestly.'
            ).toEqual([]);
        }
    );

    it.each(guardrailFiles().map(f => [f.split('/').pop()!, f]))(
        '%s uses no dynamic import of product code either',
        (_name, file) => {
            const source = withoutComments(readFileSync(file, 'utf8'));
            // `await import('../../src/auth.js')` is the obvious way around a
            // static-import rule, and the rest of this suite uses that form
            // legitimately — so it has to be checked, not assumed absent.
            const dynamic = [...source.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g)]
                .map(m => m[1])
                .filter(spec => spec.startsWith('.'))
                .filter(spec => {
                    const resolved = resolve(dirname(file), spec);
                    return resolved.includes('/src/') || resolved.includes('/public/');
                });

            expect(dynamic, `${_name} dynamically imports product code`).toEqual([]);
        }
    );
});
