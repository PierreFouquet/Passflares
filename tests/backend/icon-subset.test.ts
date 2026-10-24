// Guardrail: every Material Symbols icon referenced in the shipped HTML/JS must
// be a glyph in the bundled subset font, and in the font's documented icon list
// (public/fonts/README.md) that the font is regenerated from.
//
// The icon font is a SUBSET — only the listed glyphs are bundled. An icon whose
// glyph isn't in the subset renders as its literal ligature text (e.g. "sync",
// "remove_moderator") instead of an icon. This fails when a new icon is added
// to the UI without being added to the subset list and the .woff2 regenerated —
// exactly how the 2FA-section icons (sync / password / remove_moderator)
// shipped broken, and later seven of the Recent activity icons (manage_accounts,
// verified_user, …), which JS sets from a lookup table and the original
// static-markup-only scan never saw.
//
// Three checks, because each source of truth can drift from the others:
//   code ⊆ font    what the browser actually renders (read from the .woff2)
//   code ⊆ list    so regenerating from the list keeps every icon in use
//   list ⊆ font    a list edited without regenerating, or a stale entry

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';
import { brotliDecompressSync } from 'node:zlib';

const PUBLIC_DIR = resolve('public');
const FONT_README = join(PUBLIC_DIR, 'fonts', 'README.md');
const FONT_FILE = join(PUBLIC_DIR, 'fonts', 'material-symbols', 'MaterialSymbolsRounded.woff2');

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

// ── Reading the icon names out of the .woff2 ─────────────────────────────
//
// Material Symbols draws an icon by ligature: the letters of its name are
// substituted with the icon glyph (GSUB lookup type 4). So the names the font
// can render are the ligature inputs, spelled back through cmap. WOFF2 stores
// the sfnt tables brotli-compressed; only glyf/loca/hmtx are ever transformed,
// so cmap and GSUB come out as plain table bytes.

// WOFF2 spec §5.1: a table's tag is either an index into this list or, at 63,
// spelled out in the next four bytes.
const WOFF2_KNOWN_TAGS = [
    'cmap', 'head', 'hhea', 'hmtx', 'maxp', 'name', 'OS/2', 'post', 'cvt ', 'fpgm',
    'glyf', 'loca', 'prep', 'CFF ', 'VORG', 'EBDT', 'EBLC', 'gasp', 'hdmx', 'kern',
    'LTSH', 'PCLT', 'VDMX', 'vhea', 'vmtx', 'BASE', 'GDEF', 'GPOS', 'GSUB', 'EBSC',
    'JSTF', 'MATH', 'CBDT', 'CBLC', 'COLR', 'CPAL', 'SVG ', 'sbix', 'acnt', 'avar',
    'bdat', 'bloc', 'bsln', 'cvar', 'fdsc', 'feat', 'fmtx', 'fvar', 'gvar', 'hsty',
    'just', 'lcar', 'mort', 'morx', 'opbd', 'prop', 'trak', 'Zapf', 'Silf', 'Glat',
    'Gloc', 'Feat', 'Sill'
];

function woff2Tables(buf: Buffer): Map<string, Buffer> {
    if (buf.toString('latin1', 0, 4) !== 'wOF2') throw new Error('not a WOFF2 file');
    const numTables = buf.readUInt16BE(12);
    const compressedLength = buf.readUInt32BE(20);
    let pos = 48;
    const readBase128 = (): number => {
        let value = 0;
        for (let i = 0; i < 5; i++) {
            const byte = buf[pos++];
            value = value * 128 + (byte & 0x7f);
            if (!(byte & 0x80)) return value;
        }
        throw new Error('malformed UIntBase128 in WOFF2 table directory');
    };
    const entries: { tag: string; length: number }[] = [];
    for (let i = 0; i < numTables; i++) {
        const flags = buf[pos++];
        let tag = WOFF2_KNOWN_TAGS[flags & 0x3f];
        if ((flags & 0x3f) === 63) {
            tag = buf.toString('latin1', pos, pos + 4);
            pos += 4;
        }
        const version = flags >> 6;
        const origLength = readBase128();
        // glyf/loca: version 3 is the null transform; everything else: version 0.
        const transformed = tag === 'glyf' || tag === 'loca' ? version !== 3 : version !== 0;
        entries.push({ tag, length: transformed ? readBase128() : origLength });
    }
    const data = brotliDecompressSync(buf.subarray(pos, pos + compressedLength));
    const tables = new Map<string, Buffer>();
    let offset = 0;
    for (const { tag, length } of entries) {
        tables.set(tag, data.subarray(offset, offset + length));
        offset += length;
    }
    return tables;
}

// glyph id → character, from the cmap format 4 (BMP) subtable. Ligature
// components are the ASCII letters, digits and '_' of icon names.
function charsByGlyph(cmap: Buffer): Map<number, string> {
    const chars = new Map<number, string>();
    for (let i = 0; i < cmap.readUInt16BE(2); i++) {
        const sub = cmap.readUInt32BE(4 + i * 8 + 4);
        if (cmap.readUInt16BE(sub) !== 4) continue;
        const segX2 = cmap.readUInt16BE(sub + 6);
        const ends = sub + 14;
        const starts = ends + segX2 + 2;
        const deltas = starts + segX2;
        const rangeOffsets = deltas + segX2;
        for (let s = 0; s < segX2; s += 2) {
            const start = cmap.readUInt16BE(starts + s);
            const end = cmap.readUInt16BE(ends + s);
            const delta = cmap.readInt16BE(deltas + s);
            const rangeOffset = cmap.readUInt16BE(rangeOffsets + s);
            for (let c = start; c <= end && c !== 0xffff; c++) {
                let glyph = (c + delta) & 0xffff;
                if (rangeOffset) {
                    const id = cmap.readUInt16BE(rangeOffsets + s + rangeOffset + (c - start) * 2);
                    glyph = id && (id + delta) & 0xffff;
                }
                if (glyph && !chars.has(glyph)) chars.set(glyph, String.fromCharCode(c));
            }
        }
    }
    if (chars.size === 0) throw new Error('no cmap format 4 subtable in the icon font');
    return chars;
}

function coverageGlyphs(t: Buffer, off: number): number[] {
    const glyphs: number[] = [];
    const count = t.readUInt16BE(off + 2);
    if (t.readUInt16BE(off) === 1) {
        for (let i = 0; i < count; i++) glyphs.push(t.readUInt16BE(off + 4 + i * 2));
    } else {
        for (let i = 0; i < count; i++) {
            const end = t.readUInt16BE(off + 6 + i * 6);
            for (let g = t.readUInt16BE(off + 4 + i * 6); g <= end; g++) glyphs.push(g);
        }
    }
    return glyphs;
}

function fontIcons(): Set<string> {
    const tables = woff2Tables(readFileSync(FONT_FILE));
    const chars = charsByGlyph(tables.get('cmap')!);
    const gsub = tables.get('GSUB')!;
    const names = new Set<string>();
    const lookupList = gsub.readUInt16BE(8);
    for (let i = 0; i < gsub.readUInt16BE(lookupList); i++) {
        const lookup = lookupList + gsub.readUInt16BE(lookupList + 2 + i * 2);
        const type = gsub.readUInt16BE(lookup);
        for (let j = 0; j < gsub.readUInt16BE(lookup + 4); j++) {
            let sub = lookup + gsub.readUInt16BE(lookup + 6 + j * 2);
            if (type === 7) {
                if (gsub.readUInt16BE(sub + 2) !== 4) continue;
                sub += gsub.readUInt32BE(sub + 4); // extension → the real subtable
            } else if (type !== 4) continue;
            const firsts = coverageGlyphs(gsub, sub + gsub.readUInt16BE(sub + 2));
            for (let k = 0; k < gsub.readUInt16BE(sub + 4); k++) {
                const set = sub + gsub.readUInt16BE(sub + 6 + k * 2);
                for (let l = 0; l < gsub.readUInt16BE(set); l++) {
                    const lig = set + gsub.readUInt16BE(set + 2 + l * 2);
                    const glyphs = [firsts[k]];
                    for (let c = 1; c < gsub.readUInt16BE(lig + 2); c++) glyphs.push(gsub.readUInt16BE(lig + 2 + c * 2));
                    const letters = glyphs.map((g) => chars.get(g));
                    if (letters.every(Boolean)) names.add(letters.join(''));
                }
            }
        }
    }
    return names;
}

// ── Icon names used by the shipped HTML/JS ───────────────────────────────
//
// Static markup, plus the JS idioms that set an icon from a value:
//   - `<span class="icon">name</span>`, in HTML and in JS template strings;
//   - on a line that mentions an icon, a literal assigned to textContent or
//     taken as a ternary branch / object value (`icon: 'shield'`,
//     `? 'visibility_off' : 'visibility'`) — not one compared against;
//   - `['Human label', 'name']` pairs, the shape of settings.js's
//     ACTIVITY_LABELS table, which is how the activity icons slipped through;
//   - the values of a `const …ICONS = { … }` map (snackbar.js).
// Dynamic `${...}` interpolations are resolved by these, not read directly.
function usedIcons(): Map<string, string[]> {
    const used = new Map<string, string[]>();
    const add = (name: string, file: string) => {
        const list = used.get(name) ?? [];
        if (!list.includes(file)) list.push(file);
        used.set(name, list);
    };
    for (const file of walk(PUBLIC_DIR).filter((p) => /\.(html|js|mjs)$/i.test(p))) {
        const text = readFileSync(file, 'utf8');
        const rel = relative(process.cwd(), file);
        for (const m of text.matchAll(/<span class="icon[^"]*"[^>]*>([a-z0-9_]+)<\/span>/g)) add(m[1], rel);
        if (!/\.m?js$/i.test(file)) continue;
        for (const line of text.split('\n')) {
            if (!/icon/i.test(line) || /^\s*(\/\/|\*)/.test(line)) continue;
            for (const m of line.matchAll(/(?:textContent\s*=|\?|:)\s*'([a-z0-9_]+)'/g)) add(m[1], rel);
        }
        for (const m of text.matchAll(/\[\s*'[A-Z][^'\n]*'\s*,\s*'([a-z0-9_]+)'\s*\]/g)) add(m[1], rel);
        for (const map of text.matchAll(/const \w*ICONS\w* = \{([\s\S]*?)\};/g)) {
            for (const m of map[1].matchAll(/:\s*'([a-z0-9_]+)'/g)) add(m[1], rel);
        }
    }
    return used;
}

const missingFrom = (names: Set<string>, used: Map<string, string[]>) =>
    [...used].filter(([name]) => !names.has(name)).map(([name, files]) => `${name} — used in ${files.join(', ')}`);

describe('Material Symbols icon subset', () => {
    it('every used icon is a glyph in the bundled .woff2', () => {
        const missing = missingFrom(fontIcons(), usedIcons());
        expect(
            missing,
            'Icons used in the UI that the subset font cannot draw (they render as text). Add them to ' +
            "public/fonts/README.md's list and regenerate the .woff2 (steps in that file):\n  " +
            missing.join('\n  ')
        ).toEqual([]);
    });

    it('every used icon is in the documented subset list', () => {
        const missing = missingFrom(subsetIcons(), usedIcons());
        expect(
            missing,
            "Icons used in the UI but missing from public/fonts/README.md's list, so the next " +
            'regeneration would drop them:\n  ' + missing.join('\n  ')
        ).toEqual([]);
    });

    it('every icon in the documented list is in the bundled .woff2', () => {
        const font = fontIcons();
        const stale = [...subsetIcons()].filter((name) => !font.has(name));
        expect(
            stale,
            "Listed in public/fonts/README.md but not in the .woff2: regenerate the font, or drop " +
            'the entry if it is not a Material Symbols name:\n  ' + stale.join('\n  ')
        ).toEqual([]);
    });

    it('sanity: the scans still see the static and the JS-set icons', () => {
        const used = usedIcons();
        expect(used.size).toBeGreaterThan(20);
        // One per JS idiom above, so a scan that silently stops matching fails here.
        expect(used.get('visibility_off')).toBeDefined();                     // ternary on an icon line
        expect(used.get('manage_accounts')).toEqual(['public/js/pages/settings.js']); // label pair
        expect(used.get('info')).toContain('public/js/snackbar.js');           // ICONS map
        // The font reader itself: ligatures come back as names, aliases included.
        expect(fontIcons().has('home')).toBe(true);
    });
});
