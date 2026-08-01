#!/usr/bin/env node
// Copies the @noble/hashes files needed for Argon2id into public/vendor/, so the
// browser can import them directly.
//
// public/js/ has no build step — everything under public/ is served raw. Argon2id
// has no WebCrypto equivalent, so the one pure-JS implementation we already trust
// (and already depend on server-side) gets vendored rather than re-implemented.
//
// Run `node scripts/vendor-noble.mjs` after bumping @noble/hashes.
// tests/frontend/vendor-integrity.test.js fails if the copies drift.

import { readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

export const NOBLE_SRC = resolve(repoRoot, 'node_modules/@noble/hashes');
export const NOBLE_DEST = resolve(repoRoot, 'public/vendor/noble-hashes');

// Transitive closure of `import` specifiers reachable from argon2.js, resolved by
// hand so the vendored set stays minimal and auditable:
//   argon2  -> blake2, _u64, utils
//   blake2  -> _blake, _md, _u64, utils
//   _blake  -> utils
//   _md     -> utils
export const NOBLE_FILES = [
    'argon2.js',
    'blake2.js',
    '_blake.js',
    '_md.js',
    '_u64.js',
    'utils.js'
];

// Sourcemap comments point at .map files we don't vendor; strip them so the
// browser devtools don't emit 404s for every import.
export function transform(source) {
    return source.replace(/^\/\/# sourceMappingURL=.*$\n?/gm, '');
}

export function vendoredContent(file) {
    return transform(readFileSync(join(NOBLE_SRC, file), 'utf8'));
}

function main() {
    mkdirSync(NOBLE_DEST, { recursive: true });

    // Remove anything previously vendored that is no longer in the closure.
    for (const existing of readdirSync(NOBLE_DEST)) {
        if (!NOBLE_FILES.includes(existing) && existing !== 'README.md') {
            unlinkSync(join(NOBLE_DEST, existing));
        }
    }

    for (const file of NOBLE_FILES) {
        writeFileSync(join(NOBLE_DEST, file), vendoredContent(file));
        process.stdout.write(`vendored ${file}\n`);
    }

    const version = JSON.parse(
        readFileSync(join(NOBLE_SRC, 'package.json'), 'utf8')
    ).version;

    writeFileSync(join(NOBLE_DEST, 'README.md'), `# Vendored @noble/hashes

Copied verbatim from \`node_modules/@noble/hashes\` at version **${version}** by
\`scripts/vendor-noble.mjs\`. Do not edit these files by hand.

Only the Argon2id closure is vendored (${NOBLE_FILES.join(', ')}). \`public/js/\`
has no build step, and Argon2id has no WebCrypto equivalent, so the browser needs
these as plain ES modules.

To update: bump \`@noble/hashes\` in \`package.json\`, run \`npm install\`, then
\`node scripts/vendor-noble.mjs\`. \`tests/frontend/vendor-integrity.test.js\`
fails if these copies drift from the installed package.

Licensed MIT, same as upstream.
`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
