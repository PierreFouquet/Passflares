// Known-answer vectors for the Argon2id the browser actually runs (#83, #89 §1).
//
// Three things about the KDF were already pinned before this file existed:
//
//   * the cost profile — zero-knowledge-invariants.test.js asserts ARGON2_PARAMS
//     is exactly { m: 47104, t: 1, p: 1, len: 32 }
//   * the vendored copy — vendor-integrity.test.ts asserts public/vendor/ is
//     byte-identical to the installed @noble/hashes
//   * self-consistency — keys.test.js asserts the same password and salt derive
//     the same master key twice running
//
// The output itself was not. Nothing in the suite said what bytes
// Argon2id(password, salt, ARGON2_PARAMS) is supposed to produce, and none of
// the three above can tell you: the params can be unchanged, the vendored copy
// can match node_modules perfectly, and the derivation can agree with itself all
// day, while `npm update` quietly swaps in an implementation that returns
// different bytes for the same inputs.
//
// That is not a hypothetical shape of bug. It is the ordinary consequence of a
// dependency bump, it is invisible in review — a lockfile line — and its blast
// radius is total: masterKey feeds authSecret and kek, so every existing user
// is locked out of a vault whose ciphertext is still perfectly intact. There is
// no recovery path, because the password that opens it no longer maps to the
// key that sealed it.
//
// So the vectors below are hardcoded. They were generated once, checked against
// a second implementation, and are never to be regenerated to make this file
// pass.
//
// ── If this file goes red ────────────────────────────────────────────────────
//
// Do not update the expected values. A red assertion here means the derivation
// changed, and the question to answer is not "what are the new bytes" but "what
// happens to everyone who already has a vault". Revert the change that moved
// it. If the move is genuinely wanted — a deliberate cost increase, say — it
// needs a migration that re-derives under the new profile while the old one can
// still open the vault, and these vectors get a second set beside them rather
// than an edit in place.

import { describe, it, expect } from 'vitest';
import { argon2id } from '../../public/vendor/noble-hashes/argon2.js';
import { ARGON2_PARAMS } from '../../public/js/constants.js';

const TEXT = new TextEncoder();

const toHex = (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => Uint8Array.from(hex.match(/.{2}/g).map(b => parseInt(b, 16)));

describe('Argon2id known-answer vectors', () => {
    // The specification's own vector, not one this project generated. Every
    // other assertion in this file pins what *our* build does; this one pins it
    // to something external, so a vendored implementation that is merely
    // self-consistent — and wrong — still fails.
    //
    // RFC 9106 §5.3: v=0x13, p=4, m=32 KiB, t=3, 32-byte tag, over a password of
    // 32 0x01 bytes, salt of 16 0x02, secret of 8 0x03, associated data of 12
    // 0x04. The secret and associated-data inputs are unused by this app but are
    // part of the published vector, so they are supplied here.
    it('reproduces the RFC 9106 §5.3 Argon2id test vector', () => {
        const tag = argon2id(new Uint8Array(32).fill(0x01), new Uint8Array(16).fill(0x02), {
            version: 0x13,
            p: 4,
            m: 32,
            t: 3,
            dkLen: 32,
            key: new Uint8Array(8).fill(0x03),
            personalization: new Uint8Array(12).fill(0x04)
        });

        expect(toHex(tag)).toBe(
            '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659'
        );
    });

    // Deliberately driven by the imported ARGON2_PARAMS rather than a literal
    // copy of the numbers. That couples the vectors to the profile in
    // constants.js, so raising the cost fails here too — which is correct, since
    // raising it locks out every existing vault exactly as surely as changing
    // the algorithm does.
    describe('the production profile, as shipped in public/js/constants.js', () => {
        const VECTORS = [
            {
                name: 'an ordinary passphrase',
                password: 'correct horse battery staple',
                saltHex: 'aabbccddeeff00112233445566778899',
                expected: '318080735530732b6f129ae0f94fc68ff6cfd2c150e77dbaf7612a04b5d6d7b9'
            },
            {
                // Non-ASCII is the case a UTF-8 handling change would break, and
                // it would break it for a subset of users rather than all of
                // them — the kind of regression that reaches production.
                name: 'a password outside ASCII',
                password: 'pässwörd ✓ 🔐',
                saltHex: 'ffeeddccbbaa99887766554433221100',
                expected: '60a98131c69adaf9bbcc45aef0a55ecbf9ed5f0369782dd66409146c4ebba5e8'
            },
            {
                // Not reachable through the UI, but it pins the boundary rather
                // than leaving it to whatever an empty input happens to do.
                name: 'an empty password',
                password: '',
                saltHex: '00000000000000000000000000000000',
                expected: '4adca9bd0ced190674d70fdeef8d5fbe7de26c0d8501304e8c4e621889f01739'
            }
        ];

        it.each(VECTORS)('derives the pinned master key for $name', ({ password, saltHex, expected }) => {
            const derived = argon2id(TEXT.encode(password), fromHex(saltHex), {
                m: ARGON2_PARAMS.m,
                t: ARGON2_PARAMS.t,
                p: ARGON2_PARAMS.p,
                dkLen: ARGON2_PARAMS.len
            });

            expect(toHex(derived)).toBe(expected);
        });

        it('derives a different key for a different salt', () => {
            // The vectors above would all still pass if the salt were ignored;
            // this is what says it is not.
            const opts = {
                m: ARGON2_PARAMS.m,
                t: ARGON2_PARAMS.t,
                p: ARGON2_PARAMS.p,
                dkLen: ARGON2_PARAMS.len
            };
            const password = TEXT.encode(VECTORS[0].password);

            const other = argon2id(password, fromHex('00112233445566778899aabbccddeeff'), opts);

            expect(toHex(other)).not.toBe(VECTORS[0].expected);
        });
    });
});
