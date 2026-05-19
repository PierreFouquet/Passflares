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
    handleAddMemberToOrganization
} from './organizations.js';
import { CustomRequest, Env } from './types.js';
import { jsonResponse } from './utils.js';

const router = Router();

// Security headers for all API responses
const SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src https://challenges.cloudflare.com"
};

const ALLOWED_ORIGINS = [
    'https://pierrefouquet.co.uk',
    'https://passflares.pierrefouquet93.workers.dev',
    'https://prerelease.passflares.pierrefouquet93.workers.dev',
    'https://api.pierrefouquet.co.uk',
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

// --- Vault routes ---
router.post('/api/vaults', withAuth, handleCreateVault);
router.get('/api/vaults', withAuth, handleGetVaults);
router.put('/api/vaults/:vaultId/data', withAuth, withVaultPermission('write'), handleUploadVault);
router.get('/api/vaults/:vaultId/data', withAuth, withVaultPermission('read'), handleDownloadVault);
router.delete('/api/vaults/:vaultId', withAuth, withVaultPermission('manage'), handleDeleteVault);

// --- Organization routes ---
router.post('/api/organizations', withAuth, handleCreateOrganization);
router.get('/api/organizations', withAuth, handleGetOrganizations);
router.post('/api/organizations/:orgId/members', withAuth, handleAddMemberToOrganization);

// --- Catch-all: serve static assets ---
router.all('*', (request: Request, env: Env) => env.ASSETS.fetch(request));

// --- Worker fetch handler ---
export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        try {
            if (request.method === 'OPTIONS') {
                return handleCorsPreflight(request);
            }

            const response = await router.handle(request, env, ctx);

            // Only apply API security/CORS headers to /api/* responses
            const url = new URL(request.url);
            if (url.pathname.startsWith('/api/')) {
                return applyHeaders(
                    applyHeaders(response, SECURITY_HEADERS),
                    getCorsHeaders(request)
                );
            }
            return response;
        } catch (err: unknown) {
            console.error('Request processing failed:', err);
            const errorResponse = jsonResponse({ message: 'Service unavailable' }, 500);
            return applyHeaders(
                applyHeaders(errorResponse, SECURITY_HEADERS),
                getCorsHeaders(request)
            );
        }
    }
};
