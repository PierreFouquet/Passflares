// Repo-level static audit of public/ for common security smells.
//
// These tests grep the on-disk assets that ship to users — anything they
// find runs in the browser, so we want to keep them clean of mixed-content
// URLs, PEM material, leftover debug calls, and inline <script> blocks.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';

const PUBLIC_DIR = resolve('public');

function walk(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        const stat = statSync(full);
        if (stat.isDirectory()) walk(full, out);
        else out.push(full);
    }
    return out;
}

function filesByExt(...exts: string[]): string[] {
    const lower = exts.map((e) => e.toLowerCase());
    return walk(PUBLIC_DIR).filter((p) =>
        lower.some((e) => p.toLowerCase().endsWith(e))
    );
}

function read(path: string): string {
    return readFileSync(path, 'utf8');
}

function rel(path: string): string {
    return relative(process.cwd(), path);
}

describe('public/ — mixed-content audit', () => {
    it('no http:// URLs in HTML/JS/CSS (would trigger mixed-content blocks)', () => {
        const offenders: string[] = [];
        for (const file of filesByExt('.html', '.js', '.mjs', '.css')) {
            const text = read(file);
            // Allow http:// inside comments that explicitly mark them as
            // references (e.g. `// see http://example.com/spec`), but flag
            // anything else.
            const matches = text.match(/http:\/\/[^\s"'<>)]+/g) ?? [];
            for (const m of matches) {
                // Local-dev addresses are fine — they never reach a browser
                // that's loaded the site over HTTPS.
                if (/^http:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(m)) continue;
                // XML/SVG namespace URIs are URN-like identifiers, not real
                // network fetches — http://www.w3.org/2000/svg etc.
                if (/^http:\/\/www\.w3\.org\//.test(m)) continue;
                offenders.push(`${rel(file)}: ${m}`);
            }
        }
        expect(offenders, `Mixed-content URLs found:\n${offenders.join('\n')}`).toEqual([]);
    });
});

describe('public/ — credential / key material audit', () => {
    it('no PEM-encoded private keys in any public file', () => {
        const offenders: string[] = [];
        for (const file of walk(PUBLIC_DIR)) {
            const text = read(file);
            if (/-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/.test(text)) {
                offenders.push(rel(file));
            }
        }
        expect(offenders).toEqual([]);
    });

    it('no partial PEM markers', () => {
        // Scanner also flags lines that look like a PEM header without the
        // full key body — guards against accidental partial copy-paste.
        const offenders: string[] = [];
        for (const file of walk(PUBLIC_DIR)) {
            const text = read(file);
            if (/-----BEGIN [A-Z ]+-----/.test(text) && !/-----END [A-Z ]+-----/.test(text)) {
                offenders.push(rel(file));
            }
        }
        expect(offenders).toEqual([]);
    });
});

describe('public/js/** — debug residue', () => {
    it('no console.log or debugger left in shipped JS', () => {
        const offenders: string[] = [];
        for (const file of filesByExt('.js', '.mjs')) {
            if (!file.includes('/js/') && !file.includes('\\js\\')) continue;
            const text = read(file);
            const lines = text.split('\n');
            lines.forEach((line, i) => {
                // console.warn / console.error are legitimate error paths.
                if (/\bconsole\.log\b/.test(line)) {
                    offenders.push(`${rel(file)}:${i + 1} ${line.trim()}`);
                }
                if (/\bdebugger\b/.test(line) && !line.trim().startsWith('//')) {
                    offenders.push(`${rel(file)}:${i + 1} ${line.trim()}`);
                }
            });
        }
        expect(offenders, `Debug residue found:\n${offenders.join('\n')}`).toEqual([]);
    });
});

describe('public/**/*.html — inline script audit', () => {
    it('no inline <script> blocks with body content', () => {
        // Inline scripts force CSP to allow 'unsafe-inline' or a nonce —
        // we don't want either. External `<script src="…">` is fine.
        const offenders: string[] = [];
        for (const file of filesByExt('.html')) {
            const text = read(file);
            // Match <script ...> ... </script> with any body that has
            // non-whitespace content. The closing tag permits optional
            // whitespace before `>` (`</script >`) — HTML5 allows it and
            // CodeQL's js/bad-tag-filter flags the stricter form.
            const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
            for (const match of text.matchAll(re)) {
                const attrs = match[1] ?? '';
                const body = (match[2] ?? '').trim();
                if (body && !/\bsrc\s*=/.test(attrs)) {
                    offenders.push(`${rel(file)}: <script${attrs}> with body`);
                }
            }
        }
        expect(offenders, `Inline <script> bodies found:\n${offenders.join('\n')}`).toEqual([]);
    });
});

describe('public/** — inline `style="..."` attribute audit', () => {
    // 1.0.3 dropped `'unsafe-inline'` from CSP `style-src` to close the
    // CSS-keylogger vector. That only works if no shipped HTML / JS template
    // re-introduces `style="..."` attributes. This test enforces it.
    it('no `style="..."` in any shipped HTML', () => {
        const offenders: string[] = [];
        for (const file of filesByExt('.html')) {
            const text = read(file);
            const lines = text.split('\n');
            lines.forEach((line, i) => {
                if (/\sstyle\s*=\s*["']/.test(line)) {
                    offenders.push(`${rel(file)}:${i + 1} ${line.trim()}`);
                }
            });
        }
        expect(
            offenders,
            `Inline style= attributes break CSP style-src 'self':\n${offenders.join('\n')}`
        ).toEqual([]);
    });

    it('no `style="..."` in any JS template literal', () => {
        const offenders: string[] = [];
        for (const file of filesByExt('.js', '.mjs')) {
            const text = read(file);
            const lines = text.split('\n');
            lines.forEach((line, i) => {
                if (/\sstyle\s*=\s*["']/.test(line)) {
                    offenders.push(`${rel(file)}:${i + 1} ${line.trim()}`);
                }
            });
        }
        expect(
            offenders,
            `Inline style= in JS templates breaks CSP:\n${offenders.join('\n')}`
        ).toEqual([]);
    });
});

describe('public/js/** — innerHTML un-escaped interpolation audit', () => {
    // For a password manager, a forgotten `escapeHTML()` in an `innerHTML`
    // template is the path to stored XSS — vault names, entry names, and org
    // names are all attacker-controllable via the sharing model. This test
    // greps every `innerHTML = \`...\`` template, extracts every `${...}`
    // interpolation, and fails on any that doesn't either pass through
    // `escapeHTML()` or match the small allowlist of statically-safe shapes.

    // Patterns the test treats as safe without `escapeHTML()`:
    //   - Anything containing escapeHTML(...)  →  already escaped
    //   - String / numeric / boolean / null literals
    //   - .length / .size / .count           →  numbers
    //   - SCREAMING_SNAKE constant references and SCREAMING_SNAKE[...] lookups
    //     →  we treat module-level UPPER_SNAKE identifiers as static maps; if
    //     you add one with attacker-controllable values that convention breaks.
    //   - Ternary `cond ? a : b` where both arms are themselves safe
    //   - Nullish coalescing `a ?? b` where both are safe
    //   - Nested template literals `` `…${…}…` `` — recurse on the inner
    //     interpolations, with literal segments treated as inert HTML.
    function splitTopLevel(expr: string, sep: string): [string, string] | null {
        // Splits on `sep` only at brace/bracket/paren depth 0 and outside
        // string/template literals. Returns the first split point.
        let depth = 0;
        let inStr: string | null = null;
        for (let i = 0; i <= expr.length - sep.length; i++) {
            const c = expr[i];
            if (inStr) {
                if (c === '\\') { i++; continue; }
                if (c === inStr) inStr = null;
                continue;
            }
            if (c === '"' || c === "'" || c === '`') { inStr = c; continue; }
            if (c === '(' || c === '[' || c === '{') { depth++; continue; }
            if (c === ')' || c === ']' || c === '}') { depth--; continue; }
            if (depth === 0 && expr.slice(i, i + sep.length) === sep) {
                return [expr.slice(0, i), expr.slice(i + sep.length)];
            }
        }
        return null;
    }

    function isSafeInterpolation(expr: string): boolean {
        const e = expr.trim();
        if (e === '') return true;
        if (e.includes('escapeHTML(')) return true;

        // Literals
        if (/^(['"]).*\1$/s.test(e)) return true;
        if (/^(-?\d+(\.\d+)?|true|false|null|undefined)$/.test(e)) return true;

        // Numeric accessors
        if (/^[a-zA-Z_$][\w.$]*\.(length|size|count)$/.test(e)) return true;

        // SCREAMING_SNAKE constant (e.g. ICONS, ROLE_LABEL) — bare reference.
        if (/^[A-Z][A-Z0-9_]*$/.test(e)) return true;
        // SCREAMING_SNAKE[anything] or SCREAMING_SNAKE.foo lookup.
        if (/^[A-Z][A-Z0-9_]*\s*\[[^\]]+\]$/.test(e)) return true;
        if (/^[A-Z][A-Z0-9_]*\.[a-zA-Z_$][\w$]*$/.test(e)) return true;

        // Ternary  cond ? a : b  →  arms must both be safe.
        const tern = splitTopLevel(e, '?');
        if (tern) {
            const arms = splitTopLevel(tern[1], ':');
            if (arms) {
                return isSafeInterpolation(arms[0]) && isSafeInterpolation(arms[1]);
            }
        }
        // Nullish coalescing  a ?? b
        const nullish = splitTopLevel(e, '??');
        if (nullish) {
            return isSafeInterpolation(nullish[0]) && isSafeInterpolation(nullish[1]);
        }
        // Logical OR  a || b — same shape, both arms must be safe.
        const or = splitTopLevel(e, '||');
        if (or) {
            return isSafeInterpolation(or[0]) && isSafeInterpolation(or[1]);
        }

        // Nested template literal — recurse on its `${...}` interpolations.
        // The literal segments are inert HTML controlled by our source.
        if (e.startsWith('`') && e.endsWith('`')) {
            const inner = e.slice(1, -1);
            const subInterps = extractInterpolations(inner);
            return subInterps.every(isSafeInterpolation);
        }

        return false;
    }

    function extractInterpolations(template: string): string[] {
        // Walks the template body, tracking `${ ... }` with full awareness of
        // string literals (single/double), nested template literals, and brace
        // nesting inside the expression. Necessary because a naive `{` / `}`
        // depth counter would close prematurely on a `}` inside a string
        // literal or nested template.
        const out: string[] = [];
        for (let i = 0; i < template.length - 1; i++) {
            if (template[i] === '$' && template[i + 1] === '{') {
                const start = i + 2;
                let j = start;
                let braceDepth = 1;
                while (j < template.length && braceDepth > 0) {
                    const c = template[j];
                    if (c === '\\') { j += 2; continue; }
                    if (c === "'" || c === '"') {
                        const q = c;
                        j++;
                        while (j < template.length && template[j] !== q) {
                            if (template[j] === '\\') j += 2;
                            else j++;
                        }
                        j++;
                        continue;
                    }
                    if (c === '`') {
                        // Nested template literal — skip it as a unit.
                        j = skipBackticked(template, j);
                        continue;
                    }
                    if (c === '{') braceDepth++;
                    else if (c === '}') { braceDepth--; if (braceDepth === 0) break; }
                    j++;
                }
                out.push(template.slice(start, j));
                i = j;
            }
        }
        return out;
    }

    function skipBackticked(text: string, start: number): number {
        // `text[start]` is the opening backtick. Walks to past the matching
        // closing backtick, honouring `${ ... }` (with its own nested
        // backticks) inside the template.
        let i = start + 1;
        while (i < text.length) {
            const c = text[i];
            if (c === '\\') { i += 2; continue; }
            if (c === '`') return i + 1;
            if (c === '$' && text[i + 1] === '{') {
                let depth = 1;
                i += 2;
                while (i < text.length && depth > 0) {
                    const cc = text[i];
                    if (cc === '\\') { i += 2; continue; }
                    if (cc === "'" || cc === '"') {
                        const q = cc;
                        i++;
                        while (i < text.length && text[i] !== q) {
                            if (text[i] === '\\') i += 2;
                            else i++;
                        }
                        i++;
                        continue;
                    }
                    if (cc === '`') { i = skipBackticked(text, i); continue; }
                    if (cc === '{') depth++;
                    else if (cc === '}') depth--;
                    i++;
                }
                continue;
            }
            i++;
        }
        return i;
    }

    function findInnerHTMLTemplates(source: string): string[] {
        // Returns every template literal body assigned (anywhere) to an
        // `innerHTML` property. Handles nested backticks correctly.
        const out: string[] = [];
        const text = source;
        for (let i = 0; i < text.length - 'innerHTML'.length; i++) {
            if (!text.startsWith('innerHTML', i)) continue;
            // Must be preceded by `.` or whitespace (not e.g. an
            // identifier ending in "innerHTML"). Cheap guard.
            const prev = i === 0 ? '' : text[i - 1];
            if (prev && !/[.\s]/.test(prev)) continue;
            let j = i + 'innerHTML'.length;
            while (j < text.length && /\s/.test(text[j])) j++;
            if (text[j] !== '=') continue;
            j++;
            while (j < text.length && /\s/.test(text[j])) j++;
            if (text[j] !== '`') continue;
            const bodyStart = j + 1;
            const after = skipBackticked(text, j);
            out.push(text.slice(bodyStart, after - 1));
            i = after;
        }
        return out;
    }

    it('every `${ ... }` inside an innerHTML template either uses escapeHTML or is statically safe', () => {
        const offenders: string[] = [];
        for (const file of filesByExt('.js', '.mjs')) {
            const text = read(file);
            for (const tpl of findInnerHTMLTemplates(text)) {
                for (const expr of extractInterpolations(tpl)) {
                    if (!isSafeInterpolation(expr)) {
                        offenders.push(`${rel(file)}: \${${expr}}`);
                    }
                }
            }
        }
        expect(
            offenders,
            [
                'Unsafe interpolations inside innerHTML templates.',
                'Wrap user-controlled values in escapeHTML(...) from ui.js,',
                'or, if the value is provably a literal / number / known-safe',
                'constant, extend the allowlist in this test.',
                '',
                ...offenders
            ].join('\n')
        ).toEqual([]);
    });
});

describe('public/robots.txt — admin path exposure', () => {
    const robots = join(PUBLIC_DIR, 'robots.txt');

    it('does not list any admin / internal paths if it exists', () => {
        if (!existsSync(robots)) {
            // No robots.txt is fine — scanner only flags it informationally.
            return;
        }
        const text = read(robots).toLowerCase();
        const danger = ['admin', 'private', 'internal', '/api/', 'wp-admin', '.env'];
        const offenders = danger.filter((d) => text.includes(d));
        expect(offenders, `robots.txt mentions sensitive paths: ${offenders.join(', ')}`).toEqual([]);
    });
});

describe('public/.well-known/security.txt — RFC 9116 sanity', () => {
    const securityTxt = join(PUBLIC_DIR, '.well-known', 'security.txt');

    it('exists and carries the required fields', () => {
        expect(existsSync(securityTxt)).toBe(true);
        const text = read(securityTxt);
        expect(text).toMatch(/^Contact:/m);
        expect(text).toMatch(/^Expires:/m);
    });

    it('Expires is in the future', () => {
        const text = read(securityTxt);
        const m = text.match(/^Expires:\s*(.+)$/m);
        expect(m).toBeTruthy();
        const expires = new Date(m![1].trim());
        expect(Number.isNaN(expires.getTime())).toBe(false);
        expect(expires.getTime()).toBeGreaterThan(Date.now());
    });
});
