// Guards the vendored copy of @noble/hashes under public/vendor/.
//
// public/ has no build step, so the Argon2id implementation the browser runs is a
// hand-copied snapshot rather than a resolved npm dependency. That snapshot is
// security-critical — it derives every user's master key — so it must never drift
// from the audited, version-pinned package in node_modules.
//
// If this fails after a dependency bump, run `node scripts/vendor-noble.mjs`.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { NOBLE_DEST, NOBLE_FILES, vendoredContent } from '../../scripts/vendor-noble.mjs';

describe('public/vendor/noble-hashes', () => {
    it('contains exactly the declared closure (plus its README)', () => {
        const present = readdirSync(NOBLE_DEST).sort();
        expect(present).toEqual([...NOBLE_FILES, 'README.md'].sort());
    });

    it.each(NOBLE_FILES)('%s is byte-identical to the installed package', (file) => {
        const vendored = readFileSync(join(NOBLE_DEST, file), 'utf8');
        expect(vendored).toBe(vendoredContent(file));
    });

    it('every relative import resolves inside the vendored set', () => {
        // A missing transitive dependency would only surface as a 404 in the
        // browser at login time — i.e. exactly when it matters most.
        const unresolved: string[] = [];
        for (const file of NOBLE_FILES) {
            const source = readFileSync(join(NOBLE_DEST, file), 'utf8');
            for (const m of source.matchAll(/from\s+["'](\.\/[^"']+)["']/g)) {
                const target = m[1].replace('./', '');
                if (!NOBLE_FILES.includes(target)) unresolved.push(`${file} -> ${m[1]}`);
            }
        }
        expect(unresolved, unresolved.join('\n')).toEqual([]);
    });

    it('carries no sourceMappingURL comments (the .map files are not vendored)', () => {
        for (const file of NOBLE_FILES) {
            const source = readFileSync(join(NOBLE_DEST, file), 'utf8');
            expect(source, file).not.toMatch(/sourceMappingURL/);
        }
        expect(existsSync(join(NOBLE_DEST, 'argon2.js.map'))).toBe(false);
    });
});
