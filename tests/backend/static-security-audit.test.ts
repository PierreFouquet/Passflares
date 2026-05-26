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
            // non-whitespace content.
            const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
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
