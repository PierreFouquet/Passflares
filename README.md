# Passflares

A modern and secure password manager which runs on the Cloudflare Stack.

## Features

* **Zero-knowledge key hierarchy:** your master password never leaves your browser. It is stretched with Argon2id, then split into two independent values: an authentication secret sent to the server, and a key-encryption key that stays local. The server cannot derive any vault key from what it stores. See [Security model](#security-model).
* **Client-Side Encryption:** All sensitive vault data is encrypted in your browser with AES-256-GCM before being sent to Cloudflare R2.
* **Serverless Architecture:** Cloudflare Workers for backend logic, D1 for metadata, R2 for encrypted vault blobs, and a Durable Object for the brute-force limiter — global performance with no servers to run.
* **Organisations & Shared Vaults:** Create organisations, invite members, assign Member / Admin / Owner roles, and share vaults across a team. Each vault has its own key, wrapped separately for every member.
* **Password Generator:** Built-in cryptographically-strong generator inside the entry composer.
* **Password Strength & Re-use Detection:** Dashboard surfaces weak and re-used passwords across decrypted vaults.
* **Safe Master Password Change:** Changing your master password re-seals a single key blob. Vault contents are never rewritten, so an interrupted change cannot damage your data.
* **Two-Factor Authentication:** TOTP authenticator apps with single-use recovery codes.
* **Inactivity Logout:** Automatic session termination (5 minutes) for enhanced security.
* **Rate Limiting:** Failed login attempts are rate-limited per account *and* per IP by a
  Durable Object, with exponential backoff.
* **Audit Logging:** Sensitive actions are written to a server-side audit log, readable by
  the account they belong to under **Settings → Recent activity**, and swept after 90 days.
* **Data Export:** Export your encrypted vault data for backup.
* **Theme & Density Preferences:** Dark / light / system themes, comfortable / compact density, accent colour, and shape — persisted per user.
* **Self-hosted Fonts:** No third-party font CDN calls; Inter and a Material Symbols subset are served from the worker.

## Project Structure

```plaintext
Passflares/
├── public/                          # Static frontend assets served by the Worker via the [assets] binding
│   ├── index.html                   # App shell (templates, snackbar host, nav rail)
│   ├── css/
│   │   ├── tokens.css               # Design tokens (colours, spacing, motion)
│   │   ├── theme-dark.css           # Dark theme overrides
│   │   ├── theme-light.css          # Light theme overrides
│   │   ├── density.css              # Comfortable / compact density
│   │   ├── shape.css                # Corner radius scale
│   │   ├── accent.css               # Accent colour ramps
│   │   ├── base.css                 # Reset, typography, font-face declarations
│   │   ├── app-shell.css            # App bar, nav rail, page container
│   │   └── components/              # Per-component stylesheets (button, card, dialog, drawer, etc.)
│   ├── docs/                        # User and admin documentation site
│   │   ├── index.html               # Documentation landing page (served at /docs/)
│   │   ├── user-guide.html          # Account / sign-in / master password guide
│   │   ├── vaults-guide.html        # Vault and entry management guide
│   │   ├── organisations-guide.html # Organisations, roles, and sharing guide
│   │   ├── admin-guide.html         # Admin reference (infra, secrets, migrations, audit)
│   │   ├── css/docs.css             # Docs-only styles (built on the app's design tokens)
│   │   └── js/docs.js               # Docs theme toggle / shared behaviour
│   ├── fonts/                       # Self-hosted Inter + Material Symbols subset
│   ├── img/                         # SVG logo and favicon mark
│   └── js/
│       ├── main.js                  # App bootstrap, route registration, session wiring
│       ├── router.js                # Hash-based router
│       ├── api.js                   # Fetch wrappers for the Worker API
│       ├── state.js                 # In-memory key material + cached vaults / decrypted entries
│       ├── session.js               # Inactivity timer, user info, sign-out
│       ├── ui.js                    # Template cloning, escaping, shared UI helpers
│       ├── menu.js                  # App-bar menu (theme, preferences, sign out)
│       ├── prefs.js                 # Theme / density / shape / accent persistence
│       ├── snackbar.js              # Toast notifications
│       ├── dialog.js                # Confirm dialogs
│       ├── drawer.js                # Entry detail drawer
│       ├── search.js                # Cross-vault search (Ctrl+K)
│       ├── clipboard.js             # Copy-to-clipboard with auto-clear
│       ├── constants.js             # Shared frontend constants (KDF params, HKDF info strings)
│       ├── crypto.js                # AES-256-GCM seal/open for vault contents
│       ├── keys.js                  # Key hierarchy: Argon2id, HKDF, keypairs, vault key wrapping
│       ├── kdf-worker.js            # Argon2id in a Web Worker, off the UI thread
│       ├── auth-flow.js             # Register / sign-in / legacy upgrade / password rotation
│       ├── vault-keys.js            # Vault key resolution, org vault rescue, rotation
│       ├── org-keys.js              # Re-wrapping vault keys on membership changes
│       ├── utils.js                 # Password strength, generator, helpers
│       └── pages/                   # Per-route page modules
│           ├── auth.js              # Sign-in / register
│           ├── dashboard.js         # Landing page after sign-in
│           ├── vaults.js            # Vault list + detail + entry composer
│           ├── orgs.js              # Organisations + member management
│           └── settings.js          # Account settings, master password change, 2FA, export
│   └── vendor/
│       └── noble-hashes/            # Vendored @noble/hashes Argon2id closure (public/ has no build step)
├── src/                             # Cloudflare Worker (TypeScript)
│   ├── worker.ts                    # Worker entry point + itty-router routes
│   ├── auth.ts                      # Auth params, register, login, upgrade, password change
│   ├── middleware.ts                # JWT verification + vault permission resolution
│   ├── organizations.ts             # Organisation CRUD, membership, member public keys
│   ├── vaults.ts                    # Vault metadata (D1), versioned blobs (R2), key shares
│   ├── totp.ts                      # TOTP enrollment, verification, recovery codes
│   ├── preferences.ts               # Per-user UI preferences
│   ├── auditLog.ts                  # Audit log writes / reads
│   ├── utils.ts                     # Scrypt hashing, constant-time compare, hex helpers
│   └── types.ts                     # Shared TypeScript types
├── migrations/                      # D1 schema migrations
│   ├── 0001_init.sql
│   ├── 0002_super_admin_role.sql
│   ├── 0003_user_preferences.sql
│   ├── 0004_totp_2fa.sql
│   └── 0005_key_hierarchy.sql
├── scripts/
│   ├── static-server.mjs            # Zero-dependency static server for the E2E run
│   └── vendor-noble.mjs             # Syncs the vendored Argon2id files from node_modules
├── tests/
│   ├── backend/                     # Vitest unit tests for Worker modules
│   ├── frontend/                    # Vitest tests for frontend modules (happy-dom)
│   ├── e2e/                         # Playwright end-to-end specs
│   └── mocks/                       # Shared test fixtures and mocks
├── package.json
├── tsconfig.json
├── wrangler.toml                    # Worker config (D1, R2, Durable Object, assets, cron)
├── vitest.config.ts
├── playwright.config.ts
├── LICENSE
└── README.md
```

## Getting Started

For detailed usage instructions for a user or admin, please refer to the dedicated documentation pages:

[Go to Documentation Site](https://passflares.com/docs/ "Passflares' Documentation Site")

## Development

To set up and run locally:

1. **Clone the repo** and `cd` into it.
2. **Install dependencies:** `npm install`
3. **Install / update Wrangler** if you don't already have it — see the [Cloudflare Wrangler docs](https://developers.cloudflare.com/workers/wrangler/install-and-update/).
   * You can use [nvm](https://github.com/nvm-sh/nvm) to install `Node.js` and `npm` if needed.
4. **Create a local D1 database:** `npx wrangler d1 create secure-password-db`
5. **Apply migrations locally:** `npx wrangler d1 migrations apply secure-password-db --local`
6. **Configure local secrets:** copy `.dev.vars.example` to `.dev.vars` and fill in:
   * `JWT_SECRET` — generate with `openssl rand -base64 64`
   * `TURNSTILE_KEY` — the example file contains the Cloudflare always-passes test key, which is fine for local dev
   * `TOTP_ENC_KEY` — generate with `openssl rand -base64 32`. Required: `src/totp.ts` fails closed without it, so 2FA enrollment returns 500 if it is unset.
   * `.dev.vars` is gitignored and read automatically by `wrangler dev`.
7. **Update `wrangler.toml`** with your own D1 `database_id` and R2 bucket if you're deploying. The rate-limiter Durable Object needs no ID — the `new_sqlite_classes` migration provisions it on first deploy.
8. **Run the dev server:** `npm run dev` (wraps `wrangler dev`).
9. The app is served at the URL printed by Wrangler (typically `http://127.0.0.1:8787/`).

## Testing

Tests come in two layers: fast **Vitest** unit/frontend tests and **Playwright**
browser end-to-end tests. Most commands have a one-shot runner (what CI uses)
and an interactive runner (for local development):

| Command | What it runs | When to use it |
| --- | --- | --- |
| `npm test` | Vitest unit + frontend tests once, then exits | The default check before pushing — also run by CI on every PR |
| `npm run test:watch` | Vitest in watch mode, re-running on each file change | While actively writing or iterating on unit/frontend tests locally |
| `npm run test:e2e` | Playwright e2e specs headless, then exits | Verifying full browser flows — also run by CI on every PR |
| `npm run test:e2e:ui` | Playwright UI Mode — interactive, needs a display | Debugging or authoring a failing/flaky e2e test locally |
| `npm run test:audit` | `npm audit` at the `moderate` level | Spot-checking dependencies for known vulnerabilities |
| `npm run test:security` | The security-regression subset only | A fast check after touching auth, crypto, or anything parsing untrusted input |
| `npm run preflight` | `typecheck` + `test:audit` + Vitest + Playwright | **Run this before opening a PR** |

### Layers, and what each one is for

Backend tests come in two flavours, deliberately:

- **Unit** (`tests/backend/*.test.ts`) drive handlers against a mock D1 that
  returns canned rows keyed by a SQL substring. Fast, good for branch coverage —
  but structurally unable to catch a misspelled column, a broken `ON CONFLICT`,
  or a `D1.batch()` that isn't really atomic.
- **Integration** (`tests/backend/integration/`) build a real in-memory SQLite
  database with `node:sqlite`, apply every migration in `migrations/`, and run
  the real SQL. This is where the `auth_version` upgrade's atomicity and
  rollback behaviour are actually proven, because a live account only gets one
  attempt at it.

**CodeQL runs on every pull request** and is part of the gate — do not merge a
red run. It is not reproducible locally without the CodeQL CLI, so anything it
catches should also gain a behavioural test here, so the next occurrence fails
before the push rather than after it. Two such tests exist because CodeQL found
what the local suite missed in 1.1.4:

- `tests/backend/static-server.test.ts` — a malformed URL (`GET /%`) reached an
  unguarded `decodeURIComponent` and killed the whole server process.
- The "nothing sensitive is persisted" block in
  `tests/frontend/auth-flow.test.js` — asserts no auth secret, sealed key, or
  password ever reaches `localStorage`, after every auth operation.

Both were verified to fail against the code that had the defect. A regression
test that has never been seen red is a guess.

CI runs `npm test`, `npm run test:e2e` and CodeQL on every pull request and push
to `main`; dependency auditing is handled separately by Dependabot.

## Deployment

The live site at [passflares.com](https://passflares.com) is built
by Cloudflare's GitHub integration, which watches the **`main`**
branch.

Other operational commands:

* **Manual worker deploy (Wrangler CLI):** `npm run deploy`
* **Apply D1 migrations in production:** `npx wrangler d1 migrations apply secure-password-db --remote`
* **Set production secrets:** `npx wrangler secret put JWT_SECRET`, `npx wrangler secret put TURNSTILE_KEY`, and `npx wrangler secret put TOTP_ENC_KEY`
* **Apply D1 migrations before deploying:** `npx wrangler d1 migrations apply secure-password-db --remote`. Schema changes must land ahead of the worker that depends on them.

## Security model

This section describes what the implementation actually does, and what each
control does and does not defend against. For a password manager the security
documentation is part of the product — you make trust decisions from it — so it
is written as an explicit threat model rather than a list of adjectives.

### The key hierarchy

Your master password is stretched, then split, and neither half can produce the
other:

```plaintext
masterKey  = Argon2id(password, kdfSalt, m=47104 KiB, t=1, p=1, 32 bytes)
authSecret = HKDF-SHA256(masterKey, info="passflares:auth:v2")   -> sent to the server
kek        = HKDF-SHA256(masterKey, info="passflares:kek:v2")    -> never leaves the browser
```

The server stores `scrypt(authSecret)` (N=32768, r=12, p=1). Because HKDF is
one-way and the two outputs use different `info` strings, an attacker holding
everything the server has still cannot derive `kek` — and therefore cannot
decrypt anything.

Below that sit two more layers:

* **User keypair.** Each account has a P-256 ECDH keypair. The public key is
  readable by anyone sharing an organisation with you; the private key is stored
  only as `AES-256-GCM(kek, privateKey)` and is decrypted in your browser alone.
* **Per-vault keys.** Every vault has its own random AES-256-GCM key. Entries are
  encrypted with it, and it is wrapped separately for each member via ECIES over
  their public key. Granting access writes one row; it never re-encrypts vault
  contents, and never requires the recipient to be online.

Two consequences worth stating plainly:

* Changing your master password re-seals **one** key blob. Vault ciphertext is
  never read or rewritten, so an interrupted password change cannot damage data.
* Nobody, including the operator, can recover your vaults if you forget your
  master password. That is inherent to the design, not an oversight.

### Threat model

| Threat | Defended? |
| --- | --- |
| R2 or D1 exfiltrated without code execution | **Yes** — blobs are AES-256-GCM and no key is stored |
| Network attacker / passive TLS observer | **Yes** — TLS, plus the password is never transmitted |
| Brute force against a stolen D1 dump | **Yes** — Argon2id client-side, then scrypt (N=32768, r=12) server-side |
| Compromised Worker / malicious deploy / rogue dependency | **Yes** for upgraded accounts — the worker only ever sees an auth verifier |
| Compromised *static asset* delivery (malicious JS served to the browser) | **No** — code that runs in your tab can read your keys. This is inherent to any browser-based password manager |
| XSS in the app shell | **Partially** — strict CSP with no `unsafe-inline` and no inline scripts, but the in-memory key is reachable from JS |
| Forgotten master password | **No** — by design, see above |
| Malicious or coerced organisation admin | **No** — an admin who can already open a shared vault can share its key onward |

### Migration status

Accounts created before v1.1.4 used a weaker model in which the master password
was sent to the worker and the vault key was `PBKDF2(password, storedSalt)` — so
the server held both derivation inputs. That is the subject of
`GHSA-pqm6-r3vj-mhvq`.

Those accounts upgrade automatically and silently the next time they sign in.
Until then, and only for them, the legacy behaviour still applies.

One residue is worth calling out: organisation vaults created before the upgrade
can only be re-keyed by the member who created them, because nobody else was ever
able to decrypt them ([#69](https://github.com/PierreFouquet/Passflares/issues/69)).
They are repaired the next time that member opens them. While any remain, the
account's legacy `encryption_salt` is retained server-side, so such an account is
not yet fully zero-knowledge. Once the last one is re-keyed the salt is cleared.

### Other controls

* **HSTS + tight CSP:** `Strict-Transport-Security: max-age=31536000` on
  every API response, plus a `default-src 'none'` Content Security Policy that
  disallows inline scripts and styles on the app shell. Argon2id runs in a Web
  Worker (`worker-src 'self'`) with no WASM and no `unsafe-eval`.
* **Two-factor authentication:** optional TOTP with single-use recovery codes.
  TOTP secrets are encrypted at rest with a key derived from `TOTP_ENC_KEY`.
* **Bot protection:** Cloudflare Turnstile is enforced server-side on both
  `/api/register` and `/api/login` — a missing or invalid token blocks the
  request before any DB or scrypt work happens.
* **Rate limiting:** `/api/login`, `/api/register`, the 2FA verify paths and the
  password re-authentication paths are limited by a Durable Object
  (`src/rateLimiter.ts`) — one instance per subject, doing a serialised
  read-modify-write. Credential endpoints are capped per **account as well as
  per IP**, so a distributed attacker cannot sidestep an IP cap and one abuser
  cannot lock out a shared NAT egress. Lockouts start at 15 minutes and double
  per additional failure, to a 24-hour ceiling. This replaced a KV counter,
  which could not be atomic — the read and the write were separate operations
  and reads are eventually consistent, so concurrent requests all saw the same
  pre-increment value (`GHSA-vp89-22wm-gjr8`). `/api/auth/params` returns
  deterministic decoy parameters for unknown emails, so it cannot be used to
  enumerate accounts.
* **Constant-time comparison:** stored verifiers are compared with a
  branch-free routine rather than `===`.
* **Audit logging:** every authentication, vault-management and organisation
  event is written to the D1 `audit_logs` table via `ctx.waitUntil()`, so the
  write is not cancelled when the response returns — which previously made the
  fast-return failure events (`LOGIN_FAILURE`, `AUTH_FAILURE`,
  `VAULT_ACCESS_DENIED`) the most likely of all to be lost. Each account can read
  its own events at `GET /api/users/me/audit-log`; a nightly cron deletes rows
  older than 90 days. Routine read events (vault list, vault open, preference
  changes) are deliberately not recorded — they described page loads rather than
  actions, on a table with no retention.
* **Single-use recovery codes:** redeemed by one guarded `UPDATE` whose
  `used_at IS NULL` predicate is part of the write, so concurrent presentations
  of the same code cannot both succeed (`GHSA-q9vh-jccv-9p23`).
* **Auto sign-out:** the client signs the user out after 5 minutes of
  inactivity; the JWT itself expires after 1 hour server-side.

## Forking and self-hosting

The committed `wrangler.toml` references the upstream maintainer's
Cloudflare resources (D1 database ID, R2 bucket, and the
`passflares.com` route). Those are not secrets, but they will not work
for you — `wrangler deploy` will fail with permission errors. To stand up
your own copy:

1. Copy the template: `cp wrangler.toml.example wrangler.toml`
2. Follow the comment block at the top of that file: create your own D1
   database and R2 bucket via the Wrangler CLI, then paste
   the printed IDs into `wrangler.toml`.
3. Set `JWT_SECRET` and `TURNSTILE_KEY` as Cloudflare secrets (see
   Deployment above).
4. Update the Turnstile sitekey in `public/index.html` to your own widget's
   sitekey.
5. Apply migrations: `npx wrangler d1 migrations apply secure-password-db --local` (then `--remote` once you're ready to deploy).

## License

Copyright ©️ 2025-2026 Pierre Fouquet

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a [copy of the GNU General Public License](LICENSE "License file") along with this program. If not, see [GNU.org Licenses](https://www.gnu.org/licenses/ "GNU GPL License Page").
