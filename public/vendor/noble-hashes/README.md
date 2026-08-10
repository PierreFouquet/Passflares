# Vendored @noble/hashes

Copied verbatim from `node_modules/@noble/hashes` at version **2.3.0** by
`scripts/vendor-noble.mjs`. Do not edit these files by hand.

Only the Argon2id closure is vendored (argon2.js, blake2.js, _blake.js, _md.js, _u64.js, utils.js). `public/js/`
has no build step, and Argon2id has no WebCrypto equivalent, so the browser needs
these as plain ES modules.

To update: bump `@noble/hashes` in `package.json`, run `npm install`, then
`node scripts/vendor-noble.mjs`. `tests/backend/vendor-integrity.test.ts`
fails if these copies drift from the installed package.

Licensed MIT, same as upstream.
