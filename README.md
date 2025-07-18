# Passflares
A modern and secure password manager which runs on Cloudflare Workers, D1, and R2.

Features:
---------

* **Client-Side Encryption:** All sensitive vault data is encrypted in your browser using AES-GCM before being sent to Cloudflare R2. Your Master Password never leaves your device.
* **Strong Password Hashing:** Master Passwords are securely hashed server-side using Argon2id (Scrypt implementation is used in this version).
* **Serverless Architecture:** Leverages Cloudflare Workers for backend logic, D1 for metadata, and R2 for encrypted data storage, offering global performance and scalability.
* **Modular Design:** Clean separation of frontend and backend code for easy maintenance and future expansion.
* **Inactivity Logout:** Automatic session termination for enhanced security.
* **Master Password Change with Re-encryption:** Secure process to update your master password, including re-encryption of all your stored data.
* **Data Export:** Ability to export your encrypted vault data for backup.

Project Structure:
------------------

```
Passflares/
├── public/                       # Frontend (HTML, CSS, JS) - Deployed to Cloudflare Pages (via Worker)
│   ├── index.html
│   ├── css/
│   │   ├── docs.css              # Stylesheet for the documentation part of the site
│   │   └── style.css             # Stylesheet for the password managemenent part of the site
│   ├── docs/                     # The area of the site for user/admin guides
│   │   ├── docs.html
│   │   ├── user-guide.html       # The user guides
│   │   └── admin-guide.html      # The admin guides
│   ├── js/
│   │   ├── main.js               # Main application logic and event handling
│   │   ├── api.js                # API client for Worker interactions
│   │   ├── crypto.js             # Client-side encryption/decryption
│   │   ├── ui.js                 # UI manipulation and element references
│   │   ├── utils.js              # General utility functions (e.g., password strength, generate)
│   │   └── session.js            # Manages client-side session state and inactivity
├── src/                          # Backend (Cloudflare Worker) - Deployed to Cloudflare Workers
│   ├── auth.ts                   # User authentication (register, login, password change)
│   ├── auditLog.ts               # Audit logging functions
│   ├── middleware.ts             # JWT authentication and authorization checks
│   ├── organizations.ts          # Organization management
│   ├── types.ts                  # Shared TypeScript interfaces/types
│   ├── utils.ts                  # Worker-side utilities (e.g., Scrypt hashing, hex conversion)
│   ├── vaults.ts                 # Vault data management (D1 and R2 interaction)
│   └── worker.ts                 # Main Worker router and entry point
├── migrations/                   # D1 database schema migrations
│   └── 0001_init.sql
├── package.json                  # Node.js dependencies for dev/build
├── tsconfig.json                 # TypeScript configuration for backend
├── wrangler.toml                 # Cloudflare Worker configuration
├── LICENSE                       # The software License
└── README.md                     # This file you are reading right now
```

Getting Started:
----------------

For detailed usage instructions for a user or admin, please refer to the dedicated documentation pages:

[Go to Documentation Site](https://passflares.com/docs.html "Passflares' Documentation Site")

Development:
------------

To set up and run locally:

1. Clone/Create Project: This will set up the file structure as described above
2. Install Dependencies:** In the project root (`DIR/Passflares`), run: `npm install`
3. **Cloudflare Local dev Setup:**
    1. Install Wrangler CLI via the [Cloudflare Docs](https://developers.cloudflare.com/workers/wrangler/install-and-update/ "Cloudflare Wrangler Install/Update Docs")
    * **Note:** Make sure you have also installed or updated `Node.js` and `npm` as per the guide above - You can use [nvm](https://github.com/nvm-sh/nvm) to install both `Node.js` and `npm`.
    2. Create a local D1 Database: `npx wrangler d1 create secure-password-db --local` (required for local D1)
    3. Apply D1 migrations: `npx wrangler d1 migrations apply secure-password-db --local`
    4. Create the file `.dev.vars.local`
    5. Generate a JWT secret, e.g. run `openssl rand -base64 512` from any terminal
    6. Add this to the `.dev.vars.local` file in format `JWT_SECRET="<secret_here>"`
    * **Note:** If you changed anything, ensure you update the `wrangler.toml` with for the new JWT secret, D1 database name, and R2 bucket name or any other changes you made.
5. Run Locally: `npx wrangler dev --env local` (this will start the dev environment using the `.dev.vars.local` file for the secrets)
7. Access the frontend at the URL provided by the output (e.g., `http://127.0.0.1:8080/`).

License:
--------

Copyright ©️ 2025 Pierre Fouquet

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a [copy of the GNU General Public License](LICENSE "License file") along with this program. If not, see [GNU.org Licenses](https://www.gnu.org/licenses/ "GNU GPL License Page").
