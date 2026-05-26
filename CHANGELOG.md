# Changelog

All notable changes to Passflares are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
