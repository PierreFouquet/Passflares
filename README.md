# Passflares

A modern and secure password manager which runs on the Cloudflare Stack.

## Features

* **Client-Side Encryption:** All sensitive vault data is encrypted in your browser with AES-256-GCM before being sent to Cloudflare R2. Your Master Password never leaves your device.
* **Strong Password Hashing:** Master Passwords are securely hashed server-side using Scrypt.
* **Serverless Architecture:** Cloudflare Workers for backend logic, D1 for metadata, R2 for encrypted vault blobs, and KV for rate-limit counters — global performance with no servers to run.
* **Organisations & Shared Vaults:** Create organisations, invite members, assign Member / Admin / Owner roles, and share vaults across a team.
* **Password Generator:** Built-in cryptographically-strong generator inside the entry composer.
* **Password Strength & Re-use Detection:** Dashboard surfaces weak and re-used passwords across decrypted vaults.
* **Master Password Change with Re-encryption:** Change your master password — all stored data is re-encrypted client-side.
* **Inactivity Logout:** Automatic session termination (5 minutes) for enhanced security.
* **Rate Limiting:** Failed login attempts are rate-limited via KV to prevent brute-force attacks.
* **Audit Logging:** Sensitive actions are logged server-side and available to admins.
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
│   │   ├── docs.html                # Documentation landing page
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
│       ├── crypto.js                # Client-side AES-GCM encrypt/decrypt + key derivation
│       ├── state.js                 # In-memory app state (vaults, orgs, key, decrypted entries)
│       ├── session.js               # Inactivity timer, user info, sign-out
│       ├── ui.js                    # Template cloning, escaping, shared UI helpers
│       ├── menu.js                  # App-bar menu (theme, preferences, sign out)
│       ├── prefs.js                 # Theme / density / shape / accent persistence
│       ├── snackbar.js              # Toast notifications
│       ├── dialog.js                # Confirm dialogs
│       ├── drawer.js                # Entry detail drawer
│       ├── search.js                # Cross-vault search (Ctrl+K)
│       ├── clipboard.js             # Copy-to-clipboard with auto-clear
│       ├── constants.js             # Shared frontend constants
│       ├── utils.js                 # Password strength, generator, helpers
│       └── pages/                   # Per-route page modules
│           ├── auth.js              # Sign-in / register
│           ├── dashboard.js         # Landing page after sign-in
│           ├── vaults.js            # Vault list + detail + entry composer
│           ├── orgs.js              # Organisations + member management
│           └── settings.js          # Account settings, master password change, export
├── src/                             # Cloudflare Worker (TypeScript)
│   ├── worker.ts                    # Worker entry point + itty-router routes
│   ├── auth.ts                      # Register, login, master-password change
│   ├── middleware.ts                # JWT verification + role checks
│   ├── organizations.ts             # Organisation CRUD and membership
│   ├── vaults.ts                    # Vault metadata (D1) + encrypted blob storage (R2)
│   ├── preferences.ts               # Per-user UI preferences
│   ├── auditLog.ts                  # Audit log writes / reads
│   ├── utils.ts                     # Scrypt hashing, hex/base64 helpers
│   └── types.ts                     # Shared TypeScript types
├── migrations/                      # D1 schema migrations
│   ├── 0001_init.sql
│   ├── 0002_super_admin_role.sql
│   └── 0003_user_preferences.sql
├── tests/
│   ├── backend/                     # Vitest unit tests for Worker modules
│   ├── frontend/                    # Vitest tests for frontend modules (happy-dom)
│   ├── e2e/                         # Playwright end-to-end specs
│   └── mocks/                       # Shared test fixtures and mocks
├── package.json
├── tsconfig.json
├── wrangler.toml                    # Worker config (D1, R2, KV, assets)
├── vitest.config.ts
├── playwright.config.ts
├── LICENSE
└── README.md
```

## Getting Started

For detailed usage instructions for a user or admin, please refer to the dedicated documentation pages:

[Go to Documentation Site](https://pierrefouquet.co.uk/docs/docs.html "Passflares' Documentation Site")

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
   * `.dev.vars` is gitignored and read automatically by `wrangler dev`.
7. **Update `wrangler.toml`** with your own D1 `database_id`, R2 bucket, and KV namespace id if you're deploying.
8. **Run the dev server:** `npm run dev` (wraps `wrangler dev`).
9. The app is served at the URL printed by Wrangler (typically `http://127.0.0.1:8787/`).

## Testing

* **Unit + frontend tests (Vitest):** `npm test` (or `npm run test:watch`)
* **End-to-end tests (Playwright):** `npm run test:e2e` (or `npm run test:e2e:ui` for the UI runner)
* **Everything:** `npm run test:all`

## Deployment

* **Deploy the Worker (production):** `npm run deploy`
* **Apply D1 migrations in production:** `npx wrangler d1 migrations apply secure-password-db --remote`
* **Set production secrets:** `npx wrangler secret put JWT_SECRET` and `npx wrangler secret put TURNSTILE_KEY`

## License

Copyright ©️ 2025-2026 Pierre Fouquet

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a [copy of the GNU General Public License](LICENSE "License file") along with this program. If not, see [GNU.org Licenses](https://www.gnu.org/licenses/ "GNU GPL License Page").
