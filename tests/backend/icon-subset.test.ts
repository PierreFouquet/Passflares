// Guardrail: every Material Symbols icon referenced in the shipped HTML/JS must
// appear in the subset font's documented icon list (public/fonts/README.md).
//
// The icon font is a SUBSET — only the listed glyphs are bundled. A
// `<span class="icon">name</span>` whose glyph isn't in the subset renders as
// its literal ligature text (e.g. "sync", "remove_moderator") instead of an
// icon. This fails when a new icon is added to the UI without being added to
// the subset list and the .woff2 regenerated — exactly how the 2FA-section
// icons (sync / password / remove_moderator) shipped broken.
//
// Scope: this enforces the documented contract (code ⊆ list). Regenerating the
// .woff2 from that list is the manual step documented in public/fonts/README.md.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';

const PUBLIC_DIR = resolve('public');
const FONT_README = join(PUBLIC_DIR, 'fonts', 'README.md');

function walk(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) walk(full, out);
        else out.push(full);
    }
    return out;
}

// Parse the documented subset list out of the first fenced code block that
// follows the "Subset icons" bullet in the fonts README.
function subsetIcons(): Set<string> {
    const md = readFileSync(FONT_README, 'utf8');
    const block = md.match(/Subset icons[\s\S]*?\n```\n([\s\S]*?)\n```/);
    if (!block) throw new Error('Could not find the subset icon list in public/fonts/README.md');
    return new Set(block[1].split(/[\s,]+/).map((s) => s.trim()).filter(Boolean));
}

// Every distinct icon name used as a static <span class="icon">name</span> in
// shipped HTML/JS. Dynamic `${...}` interpolations are skipped (can't resolve
// statically); those glyphs are stable and already in the subset.
function usedIcons(): Map<string, string[]> {
    const used = new Map<string, string[]>();
    const re = /<span class="icon[^"]*"[^>]*>([a-z0-9_]+)<\/span>/g;
    for (const file of walk(PUBLIC_DIR).filter((p) => /\.(html|js|mjs)$/i.test(p))) {
        const text = readFileSync(file, 'utf8');
        for (const m of text.matchAll(re)) {
            const list = used.get(m[1]) ?? [];
            list.push(relative(process.cwd(), file));
            used.set(m[1], list);
        }
    }
    return used;
}

describe('Material Symbols icon subset', () => {
    it('every statically-used icon is present in the bundled subset', () => {
        const subset = subsetIcons();
        const missing: string[] = [];
        for (const [name, files] of usedIcons()) {
            if (!subset.has(name)) missing.push(`${name} — used in ${files.join(', ')}`);
        }
        expect(
            missing,
            'Icons used in the UI but missing from the subset font. Add them to ' +
            "public/fonts/README.md's list and regenerate the .woff2 (steps in that file):\n  " +
            missing.join('\n  ')
        ).toEqual([]);
    });

    it('sanity: the icon-usage scan still matches a realistic number of icons', () => {
        expect(usedIcons().size).toBeGreaterThan(20);
    });
});
