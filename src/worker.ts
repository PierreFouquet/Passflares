// src/worker.ts

import { Router } from 'itty-router';
import { authenticateRequest, checkVaultPermission } from './middleware.js';
import {
    handleRegister,
    handleLogin,
    handleAuthParams,
    handleAuthUpgrade,
    handleGetUserEncryptionSalt,
    handleGetUserPublicKey,
    handleUpdateMasterPassword,
    handleDeleteAccount
} from './auth.js';
import {
    handleCreateVault,
    handleGetVaults,
    handleUploadVault,
    handleDownloadVault,
    handleDeleteVault,
    handleCommitKeyVersion,
    handleGetVaultShare,
    handlePutVaultShares
} from './vaults.js';
import {
    handleCreateOrganization,
    handleGetOrganizations,
    handleAddMemberToOrganization,
    handleGetOrgMembers,
    handleGetOrgMemberKeys,
    handleUpdateMemberRole,
    handleRemoveMember,
    handleDeleteOrganization
} from './organizations.js';
import { handleGetPreferences, handleUpdatePreferences } from './preferences.js';
import {
    handleTotpStatus,
    handleTotpEnroll,
    handleTotpEnable,
    handleTotpDisable,
    handleRegenerateRecoveryCodes,
    handleLoginVerify2fa
} from './totp.js';
import { CustomRequest, Env } from './types.js';
import { jsonResponse } from './utils.js';

// The Durable Object class must be exported from the Worker's entrypoint for the
// runtime to instantiate it. Nothing calls it yet — this deploy exists only to
// apply the class migration, which `wrangler deploy` can do and
// `wrangler versions upload` cannot.
export { RateLimiter } from './rateLimiter.js';

const router = Router();

// Security headers common to every response (API + static assets).
const BASE_SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    // X-XSS-Protection: 0 disables legacy browser XSS auditors. Modern
    // browsers (Chrome 78+, Firefox) already removed them, and Safari's
    // mode=block auditor has been used to selectively disable JS in
    // otherwise-safe pages. Defence here is CSP, not legacy auditors.
    'X-XSS-Protection': '0',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
};

// CSP for HTML pages. Notable choices:
//   - default-src 'none' — deny-by-default; every directive below must
//     explicitly opt resources back in. Anything we forget to declare is
//     blocked, not silently allowed.
//   - script-src 'self' + Turnstile — no inline scripts (pre-paint bootstrap
//     is an external file at public/js/prefs-bootstrap.js).
//   - worker-src 'self' — Argon2id runs in a Web Worker (public/js/kdf-worker.js)
//     so the ~1s master-key derivation doesn't freeze the UI. Under
//     default-src 'none' workers are blocked unless declared. Still no
//     'unsafe-eval' and no WASM: the implementation is plain vendored ES modules.
//   - style-src 'self' — no 'unsafe-inline'. Closes the CSS-keylogger vector
//     against the master-password input that an HTML-injection bug would
//     otherwise enable. All inline `style="..."` attributes were moved to
//     utility classes in base.css; static-security-audit.test.ts enforces.
//   - object-src 'none', form-action 'self', frame-ancestors 'none' — all
//     locked down per the OWASP cheat sheet.
const HTML_CSP =
    "default-src 'none'; " +
    "script-src 'self' https://challenges.cloudflare.com; " +
    "worker-src 'self'; " +
    "style-src 'self'; " +
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self' https://api.passflares.com; " +
    "frame-src https://challenges.cloudflare.com; " +
    "manifest-src 'self'; " +
    "base-uri 'self'; " +
    "object-src 'none'; " +
    "form-action 'self'; " +
    "frame-ancestors 'none'";

// CSP for API/JSON responses — these should never load any subresource.
const API_CSP =
    "default-src 'none'; " +
    "base-uri 'none'; " +
    "frame-ancestors 'none'";

const ALLOWED_ORIGINS = [
    'https://passflares.com',
    'https://passflares.pierrefouquet93.workers.dev',
    'https://api.passflares.com',
    // Local dev origins; the worker's deployed routes are restricted to
    // passflares.com, so these only ever match when running `wrangler dev`.
    'http://localhost:8080',
    'http://localhost:5173'
];

const getCorsHeaders = (request: Request): Record<string, string> => {
    const requestOrigin = request.headers.get('Origin');
    const allowedOrigin = ALLOWED_ORIGINS.includes(requestOrigin ?? '')
        ? requestOrigin
        : 'https://passflares.com';

    return {
        'Access-Control-Allow-Origin': allowedOrigin ?? '',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
        'Vary': 'Origin'
    };
};

function handleCorsPreflight(request: Request): Response {
    return new Response(null, { status: 204, headers: getCorsHeaders(request) });
}

function applyHeaders(response: Response, extra: Record<string, string>): Response {
    const headers = new Headers(response.headers);
    for (const [key, value] of Object.entries(extra)) {
        if (value) headers.set(key, value);
    }
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
    });
}

// passflares.com is the canonical origin. `www.passflares.com` is also routed
// to this Worker, but every request to it is permanently redirected to the
// bare apex, preserving path + query. The base security headers (incl. HSTS)
// ride along so the redirect response itself is covered.
const CANONICAL_HOST = 'passflares.com';

function redirectToCanonicalHost(url: URL): Response | null {
    if (url.hostname !== `www.${CANONICAL_HOST}`) return null;
    const location = `https://${CANONICAL_HOST}${url.pathname}${url.search}`;
    return applyHeaders(
        new Response(null, { status: 301, headers: { Location: location } }),
        BASE_SECURITY_HEADERS
    );
}

// Middleware wrappers: itty-router continues when a handler returns undefined,
// but our middleware returns null to signal "continue". Convert null → undefined.
const withAuth = (req: CustomRequest, env: Env, ctx: ExecutionContext) =>
    authenticateRequest(req, env, ctx).then((r) => r ?? undefined);

const withVaultPermission = (permission: 'read' | 'write' | 'manage') =>
    (req: CustomRequest, env: Env, ctx: ExecutionContext) =>
        checkVaultPermission(req, env, permission, ctx).then((r) => r ?? undefined);

// --- Public routes (no auth required) ---
// /auth/params must be public: the client needs the Argon2id salt before it can
// produce the auth secret that would authenticate it. It returns decoy params
// for unknown emails so it isn't an account-existence oracle.
router.get('/api/auth/params', handleAuthParams);
router.post('/api/register', handleRegister);
router.post('/api/login', handleLogin);
router.post('/api/login/2fa', handleLoginVerify2fa);

// --- Authenticated user routes ---
// The auth_version 1 -> 2 upgrade. Authenticated, because the client has just
// completed a legacy login and holds a session token.
router.post('/api/auth/upgrade', withAuth, handleAuthUpgrade);
router.get('/api/users/:userId/encryption-salt', withAuth, handleGetUserEncryptionSalt);
router.get('/api/users/:userId/public-key', withAuth, handleGetUserPublicKey);
router.put('/api/users/:userId/update-password', withAuth, handleUpdateMasterPassword);
router.delete('/api/users/:userId', withAuth, handleDeleteAccount);

// --- Two-factor authentication ---
router.get('/api/2fa/status', withAuth, handleTotpStatus);
router.post('/api/2fa/enroll', withAuth, handleTotpEnroll);
router.post('/api/2fa/enable', withAuth, handleTotpEnable);
router.post('/api/2fa/disable', withAuth, handleTotpDisable);
router.post('/api/2fa/recovery-codes/regenerate', withAuth, handleRegenerateRecoveryCodes);

// --- User preferences (synced UI prefs) ---
router.get('/api/users/me/preferences', withAuth, handleGetPreferences);
router.put('/api/users/me/preferences', withAuth, handleUpdatePreferences);

// --- Vault routes ---
router.post('/api/vaults', withAuth, handleCreateVault);
router.get('/api/vaults', withAuth, handleGetVaults);
// Registered before the /:vaultId routes so 'key-version' isn't captured as an ID.
// Permission is checked per vault inside the handler, since it spans several.
router.post('/api/vaults/key-version/commit', withAuth, handleCommitKeyVersion);
router.put('/api/vaults/:vaultId/data', withAuth, withVaultPermission('write'), handleUploadVault);
router.get('/api/vaults/:vaultId/data', withAuth, withVaultPermission('read'), handleDownloadVault);
router.get('/api/vaults/:vaultId/share', withAuth, withVaultPermission('read'), handleGetVaultShare);
router.put('/api/vaults/:vaultId/shares', withAuth, withVaultPermission('manage'), handlePutVaultShares);
router.delete('/api/vaults/:vaultId', withAuth, withVaultPermission('manage'), handleDeleteVault);

// --- Organization routes ---
router.post('/api/organizations', withAuth, handleCreateOrganization);
router.get('/api/organizations', withAuth, handleGetOrganizations);
// Member routes registered before org-level DELETE to avoid path conflicts
router.get('/api/organizations/:orgId/members', withAuth, handleGetOrgMembers);
// Public keys of every member, so an admin holding a vault key can wrap it for
// them without a round trip per member.
router.get('/api/organizations/:orgId/member-keys', withAuth, handleGetOrgMemberKeys);
router.post('/api/organizations/:orgId/members', withAuth, handleAddMemberToOrganization);
router.put('/api/organizations/:orgId/members/:memberUserId', withAuth, handleUpdateMemberRole);
router.delete('/api/organizations/:orgId/members/:memberUserId', withAuth, handleRemoveMember);
router.delete('/api/organizations/:orgId', withAuth, handleDeleteOrganization);

// --- Catch-all: serve static assets ---
router.all('*', (request: Request, env: Env) => env.ASSETS.fetch(request));

function isHtmlResponse(response: Response): boolean {
    const ct = response.headers.get('Content-Type') ?? '';
    return ct.includes('text/html');
}

// Picks the right CSP (HTML vs API) and merges with the base security headers.
function withSecurityHeaders(response: Response, isApi: boolean): Response {
    const csp = isApi
        ? API_CSP
        : (isHtmlResponse(response) ? HTML_CSP : '');
    const extras: Record<string, string> = { ...BASE_SECURITY_HEADERS };
    if (csp) extras['Content-Security-Policy'] = csp;
    return applyHeaders(response, extras);
}

// --- Worker fetch handler ---
export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        try {
            const url = new URL(request.url);

            const canonicalRedirect = redirectToCanonicalHost(url);
            if (canonicalRedirect) return canonicalRedirect;

            if (request.method === 'OPTIONS') {
                return handleCorsPreflight(request);
            }

            // itty-router v5 removed the `handle` alias — only `fetch` invokes
            // the router. Because the router's proto is a Proxy that turns any
            // unknown property into a route-registration call, `router.handle(...)`
            // silently registers a bogus "HANDLE" route and returns the router
            // itself instead of a Response. That is not a type error either
            // (RouterType has an index signature), so it fails only at runtime.
            const response = await router.fetch(request, env, ctx);
            const isApi = url.pathname.startsWith('/api/');

            const secured = withSecurityHeaders(response, isApi);
            return isApi
                ? applyHeaders(secured, getCorsHeaders(request))
                : secured;
        } catch (err: unknown) {
            console.error('Request processing failed:', err);
            const errorResponse = jsonResponse({ message: 'Service unavailable' }, 500);
            return applyHeaders(
                withSecurityHeaders(errorResponse, true),
                getCorsHeaders(request)
            );
        }
    }
};
