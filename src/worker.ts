// src/worker.ts

import { Router } from 'itty-router';
import { authenticateRequest, checkVaultPermission } from './middleware.js';
import {
    handleRegister,
    handleLogin,
    handleGetUserEncryptionSalt,
    handleUpdateMasterPassword,
    handleDeleteAccount
} from './auth.js';
import {
    handleCreateVault,
    handleGetVaults,
    handleUploadVault,
    handleDownloadVault,
    handleDeleteVault
} from './vaults.js';
import {
    handleCreateOrganization,
    handleGetOrganizations,
    handleAddMemberToOrganization,
    handleGetOrgMembers,
    handleUpdateMemberRole,
    handleRemoveMember,
    handleDeleteOrganization
} from './organizations.js';
import { handleGetPreferences, handleUpdatePreferences } from './preferences.js';
import { CustomRequest, Env } from './types.js';
import { jsonResponse } from './utils.js';

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
//   - style-src 'self' — no 'unsafe-inline'. Closes the CSS-keylogger vector
//     against the master-password input that an HTML-injection bug would
//     otherwise enable. All inline `style="..."` attributes were moved to
//     utility classes in base.css; static-security-audit.test.ts enforces.
//   - object-src 'none', form-action 'self', frame-ancestors 'none' — all
//     locked down per the OWASP cheat sheet.
const HTML_CSP =
    "default-src 'none'; " +
    "script-src 'self' https://challenges.cloudflare.com; " +
    "style-src 'self'; " +
    "img-src 'self' data:; " +
    "font-src 'self'; " +
    "connect-src 'self' https://api.pierrefouquet.co.uk; " +
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
    'https://pierrefouquet.co.uk',
    'https://passflares.pierrefouquet93.workers.dev',
    'https://api.pierrefouquet.co.uk',
    // Local dev origins; the worker's deployed routes are restricted to
    // pierrefouquet.co.uk, so these only ever match when running `wrangler dev`.
    'http://localhost:8080',
    'http://localhost:5173'
];

const getCorsHeaders = (request: Request): Record<string, string> => {
    const requestOrigin = request.headers.get('Origin');
    const allowedOrigin = ALLOWED_ORIGINS.includes(requestOrigin ?? '')
        ? requestOrigin
        : 'https://pierrefouquet.co.uk';

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

// Middleware wrappers: itty-router continues when a handler returns undefined,
// but our middleware returns null to signal "continue". Convert null → undefined.
const withAuth = (req: CustomRequest, env: Env, ctx: ExecutionContext) =>
    authenticateRequest(req, env, ctx).then((r) => r ?? undefined);

const withVaultPermission = (permission: 'read' | 'write' | 'manage') =>
    (req: CustomRequest, env: Env, ctx: ExecutionContext) =>
        checkVaultPermission(req, env, permission, ctx).then((r) => r ?? undefined);

// --- Public routes (no auth required) ---
router.post('/api/register', handleRegister);
router.post('/api/login', handleLogin);

// --- Authenticated user routes ---
router.get('/api/users/:userId/encryption-salt', withAuth, handleGetUserEncryptionSalt);
router.put('/api/users/:userId/update-password', withAuth, handleUpdateMasterPassword);
router.delete('/api/users/:userId', withAuth, handleDeleteAccount);

// --- User preferences (synced UI prefs) ---
router.get('/api/users/me/preferences', withAuth, handleGetPreferences);
router.put('/api/users/me/preferences', withAuth, handleUpdatePreferences);

// --- Vault routes ---
router.post('/api/vaults', withAuth, handleCreateVault);
router.get('/api/vaults', withAuth, handleGetVaults);
router.put('/api/vaults/:vaultId/data', withAuth, withVaultPermission('write'), handleUploadVault);
router.get('/api/vaults/:vaultId/data', withAuth, withVaultPermission('read'), handleDownloadVault);
router.delete('/api/vaults/:vaultId', withAuth, withVaultPermission('manage'), handleDeleteVault);

// --- Organization routes ---
router.post('/api/organizations', withAuth, handleCreateOrganization);
router.get('/api/organizations', withAuth, handleGetOrganizations);
// Member routes registered before org-level DELETE to avoid path conflicts
router.get('/api/organizations/:orgId/members', withAuth, handleGetOrgMembers);
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
            if (request.method === 'OPTIONS') {
                return handleCorsPreflight(request);
            }

            const response = await router.handle(request, env, ctx);
            const url = new URL(request.url);
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
