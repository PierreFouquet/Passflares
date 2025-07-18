# Passflare
A modern and secure password manager which runs on the Cloudflare Workers, D1, and R2

Features:
---------

*   **Client-Side Encryption:** All sensitive vault data is encrypted in your browser using AES-GCM before being sent to Cloudflare R2. Your Master Password never leaves your device.
*   **Strong Password Hashing:** Master Passwords are securely hashed server-side using Argon2id (Scrypt implementation is used in this version).
*   **Serverless Architecture:** Leverages Cloudflare Workers for backend logic, D1 for metadata, and R2 for encrypted data storage, offering global performance and scalability.
*   **Modular Design:** Clean separation of frontend and backend code for easy maintenance and future expansion.
*   **Inactivity Logout:** Automatic session termination for enhanced security.
*   **Master Password Change with Re-encryption:** Secure process to update your master password, including re-encryption of all your stored data.
*   **Data Export:** Ability to export your encrypted vault data for backup.

Project Structure:
------------------

```
secure-password-manager/
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
│   └── 0001\_initial\_schema.sql
├── package.json                  # Node.js dependencies for dev/build
├── tsconfig.json                 # TypeScript configuration for backend
├── wrangler.toml                 # Cloudflare Worker configuration
└── README.md                     # This file you are reading right now
```

Getting Started:
----------------

For detailed deployment and usage instructions, please refer to the dedicated documentation site:

[Go to Documentation Site](https://passflare.com/docs.html)

<!DOCTYPE html>
<body>
<script type="text/javascript">
const button = document.querySelector('#openTab');
// add click event listener
button.addEventListener('click', () => {
    // open an empty window
    const tab = window.open('about:blank');
    // make an API call
    fetch('/api/validate')
        .then(res => res.json())
        .then(json => {
            // TODO: do something with JSON response
            // update the actual URL
            tab.location = 'https://passflare.com/docs.html';
            tab.focus();
        })
        .catch(err => {
            // close the empty window
            tab.close();
        });
});
</script>
</body>
</>

Development:
------------

To set up and run locally:

1.  \*\*Clone/Create Project:\*\* Set up the file structure as described above.
2.  \*\*Install Dependencies:\*\* In the project root (\`secure-password-manager/\`), run: `npm install`
3.  \*\*Cloudflare Setup:\*\*
    *   Install Wrangler CLI: `npm install -g wrangler`
    *   Login to Wrangler: `wrangler login`
    *   Create D1 Database: `wrangler d1 create secure-password-db` (Note ID and name)
    *   Apply D1 migrations: `wrangler d1 execute secure-password-db --file=./migrations/0001_initial_schema.sql`
    *   Create R2 Bucket: `wrangler r2 bucket create secure-vaults-r2`
    *   \*\*Update `wrangler.toml`:\*\* Fill in your actual \`JWT\_SECRET\`, D1 \`database\_id\`, and R2 \`bucket\_name\`.
4.  \*\*Run Locally:\*\* In the project root, run: `npm start` (This will start both the backend worker and serve the frontend).
5.  Access the frontend at the URL provided by `live-server` (e.g., `http://127.0.0.1:8080/`).

License:
--------

This project is open-source and available under the *GNU General Public License v3.0*. See the LICENSE file for details.

© 2025 Passflare. All rights reserved.
