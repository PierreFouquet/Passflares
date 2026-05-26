import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');

describe('static content shipped with the worker', () => {
    it('publishes /.well-known/security.txt with required RFC 9116 fields', () => {
        const path = resolve(repoRoot, 'public/.well-known/security.txt');
        expect(existsSync(path), 'security.txt is missing').toBe(true);
        const content = readFileSync(path, 'utf8');
        expect(content).toMatch(/^Contact:\s+/m);
        expect(content).toMatch(/^Expires:\s+\d{4}-\d{2}-\d{2}/m);
        // Expires must be in the future at test time, otherwise scanners will
        // flag the file as stale.
        const m = content.match(/^Expires:\s+(\S+)/m);
        const expires = new Date(m?.[1] ?? '');
        expect(expires.getTime()).toBeGreaterThan(Date.now());
    });

    it('does not duplicate CSP in a <meta http-equiv> tag', () => {
        // The worker is the single source of truth for CSP. A <meta> CSP in
        // index.html is the kind of thing that silently rots — a future edit
        // could weaken the meta without anyone noticing the header is now
        // overridden in browsers that honour both.
        const html = readFileSync(resolve(repoRoot, 'public/index.html'), 'utf8');
        expect(html).not.toMatch(/http-equiv=["']Content-Security-Policy["']/i);
    });

    it('does not use inline <script> blocks in index.html', () => {
        // CSP forbids 'unsafe-inline'; any inline <script>…</script> block
        // would silently fail to execute. External `<script src=…>` tags
        // are fine and not matched by this regex.
        const html = readFileSync(resolve(repoRoot, 'public/index.html'), 'utf8');
        // Match <script ...>...non-empty body...</script> but NOT
        // self-closing or src-only tags. We allow whitespace-only bodies.
        const inlineBlocks = html.match(/<script\b(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi) ?? [];
        const withBody = inlineBlocks.filter((block) => {
            const body = block.replace(/^<script\b[^>]*>/i, '').replace(/<\/script>$/i, '');
            return body.trim().length > 0;
        });
        expect(withBody, `inline scripts found: ${withBody.join('\n---\n')}`).toHaveLength(0);
    });

    it('auth forms declare method="post" so scanners do not flag GET-with-password', () => {
        const html = readFileSync(resolve(repoRoot, 'public/index.html'), 'utf8');
        const loginForm = html.match(/<form[^>]*id=["']login-form["'][^>]*>/i)?.[0] ?? '';
        const registerForm = html.match(/<form[^>]*id=["']register-form["'][^>]*>/i)?.[0] ?? '';
        expect(loginForm).toMatch(/method=["']post["']/i);
        expect(registerForm).toMatch(/method=["']post["']/i);
    });
});
