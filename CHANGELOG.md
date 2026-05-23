# Changelog

All notable changes to Passflares are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/PierreFouquet/Passflares/releases/tag/v1.0.0
