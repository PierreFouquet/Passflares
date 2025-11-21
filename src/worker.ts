// src/worker.ts

import { Router } from 'itty-router';
import { authenticateRequest, checkVaultPermission } from './middleware.js';
import { 
    handleRegister, 
    handleLogin, 
    handleGetUserEncryptionSalt, 
    handleUpdateMasterPassword 
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

// Security headers for all responses
const SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'"
};

// Fixed list of allowed origins
const ALLOWED_ORIGINS = [
    'https://pierrefouquet.co.uk',
    'https://passflares.pierrefouquet93.workers.dev',
    'https://prerelease.passflares.pierrefouquet93.workers.dev',
    'https://api.pierrefouquet.co.uk',
    'http://localhost:8080',
    'http://localhost:5173'
];

// Dynamic CORS configuration
const getCorsHeaders = (request: Request) => {
    const requestOrigin = request.headers.get('Origin');
    const allowedOrigin = ALLOWED_ORIGINS.includes(requestOrigin || '') 
        ? requestOrigin 
        : 'https://pierrefouquet.co.uk'; // Default to production

    return {
        'Access-Control-Allow-Origin': allowedOrigin || '',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
        'Vary': 'Origin'
    };
};

// Handle CORS Preflight Requests
function handleCorsPreflight(request: Request): Response {
    return new Response(null, {
        status: 204,
        headers: getCorsHeaders(request)
    });
}

// Add CORS headers to actual responses
function addCorsHeaders(response: Response, request: Request): Response {
    const corsHeaders = getCorsHeaders(request);
    const headers = new Headers(response.headers);
    
    Object.entries(corsHeaders).forEach(([key, value]) => {
        if (value) headers.set(key, value);
    });
    
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: headers
    });
}

// Add security headers to responses
function addSecurityHeaders(response: Response): Response {
    const headers = new Headers(response.headers);
    
    Object.entries(SECURITY_HEADERS).forEach(([key, value]) => {
        headers.set(key, value);
    });
    
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: headers
    });
}

// --- Endpoint Registrations (unchanged) ---
// ... [your existing endpoint registrations] ...

// --- Global Worker fetch handler ---
export default {
    async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
        try {
            // Handle CORS preflight requests
            if (request.method === 'OPTIONS') {
                return handleCorsPreflight(request);
            }

            // Process request
            const response = await router.handle(request, env, ctx);
            
            // Apply security headers to all responses
            const securedResponse = addSecurityHeaders(response);
            
            // Apply CORS headers to API responses
            return addCorsHeaders(securedResponse, request);
        } catch (err: any) {
            console.error('Request processing failed:', err);
            
            const errorResponse = jsonResponse({ 
                message: "Service unavailable"
            }, 500);
            
            const securedError = addSecurityHeaders(errorResponse);
            return addCorsHeaders(securedError, request);
        }
    },
};