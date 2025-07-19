// src/worker.ts

import { Router } from 'itty-router';
import { authenticateRequest, checkVaultPermission } from './middleware.js'; // Ensure correct path and .js extension
import { handleRegister, handleLogin, handleGetUserEncryptionSalt, handleUpdateMasterPassword } from './auth.js'; // Ensure correct path and .js extension
import { handleCreateVault, handleGetVaults, handleUploadVault, handleDownloadVault, handleDeleteVault } from './vaults.js'; // Ensure correct path and .js extension
import { handleCreateOrganization, handleGetOrganizations, handleAddMemberToOrganization } from './organizations.js'; // Ensure correct path and .js extension
import { CustomRequest, Env } from './types.js'; // Ensure correct path and .js extension
import { jsonResponse } from './utils.js'; // Ensure correct path and .js extension

const router = Router();

// CORS Headers - Apply to all responses by default
const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*', // Adjust in production to your frontend domain
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400', // Cache preflight for 24 hours
};

// Handle CORS Preflight Requests
function handleCorsPreflight(): Response {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
}

// Add CORS headers to actual responses
function addCorsHeaders(response: Response): Response {
    Object.entries(CORS_HEADERS).forEach(([key, value]) => {
        if (key !== 'Access-Control-Max-Age') { // Max-Age is for preflight only
            response.headers.set(key, value);
        }
    });
    return response;
}

// --- Public Endpoints (No Auth) ---
router.post('/api/register', handleRegister);
router.post('/api/login', handleLogin);

// --- Authenticated Endpoints (Apply `authenticateRequest` middleware) ---
// User Management
router.get('/api/users/:userId/encryption-salt', authenticateRequest as any, handleGetUserEncryptionSalt);
router.put('/api/users/:userId/update-password', authenticateRequest as any, handleUpdateMasterPassword);

// Vault Management (some require additional permission checks)
router.post('/api/vaults', authenticateRequest as any, handleCreateVault);
router.get('/api/vaults', authenticateRequest as any, handleGetVaults);

// Vault data upload/download require 'write'/'read' permission check
router.put('/api/vaults/:vaultId/data', authenticateRequest as any, async (request: CustomRequest, env: Env, ctx: ExecutionContext) => {
    const permissionResponse = await checkVaultPermission(request, env, 'write', ctx);
    if (permissionResponse) return permissionResponse;
    return handleUploadVault(request, env, ctx);
});
router.get('/api/vaults/:vaultId/data', authenticateRequest as any, async (request: CustomRequest, env: Env, ctx: ExecutionContext) => {
    const permissionResponse = await checkVaultPermission(request, env, 'read', ctx);
    if (permissionResponse) return permissionResponse;
    return handleDownloadVault(request, env, ctx);
});

// Vault deletion requires 'manage' permission
router.delete('/api/vaults/:vaultId', authenticateRequest as any, async (request: CustomRequest, env: Env, ctx: ExecutionContext) => {
    const permissionResponse = await checkVaultPermission(request, env, 'manage', ctx);
    if (permissionResponse) return permissionResponse;
    return handleDeleteVault(request, env, ctx);
});

// Organization Management
router.post('/api/organizations', authenticateRequest as any, handleCreateOrganization);
router.get('/api/organizations', authenticateRequest as any, handleGetOrganizations);
// Adding members to an organization requires current user to be an admin of that organization
router.post('/api/organizations/:orgId/members', authenticateRequest as any, handleAddMemberToOrganization);


// --- Fallback for unknown routes ---
router.all('*', () => jsonResponse({ message: 'Not Found.' }, 404));

// --- Global Worker fetch handler ---
export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        // Handle CORS preflight requests first
        if (request.method === 'OPTIONS') {
            return handleCorsPreflight();
        }

        try {
            // Route the request using itty-router
            // Cast request to CustomRequest so handlers can access `request.user`
            const response = await router.handle(request as CustomRequest, env, ctx);
            return addCorsHeaders(response);
        } catch (err: any) {
            console.error("Router error:", err);
            // Log the error for internal debugging
            // Decide how much error detail to send to client based on security policy
            return addCorsHeaders(jsonResponse({ message: "Internal Server Error", error: err.message || "Unknown error" }, 500));
        }
    },
};