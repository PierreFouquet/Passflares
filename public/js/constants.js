// public/js/constants.js

export const API_BASE_URL = '/api'; // Proxy via Cloudflare Pages rewrites
export const KDF_SALT_LENGTH = 16; // bytes
export const AES_IV_LENGTH = 12; // bytes (for GCM)
export const KDF_ITERATIONS = 600000; // Iterations for Argon2id/PBKDF2
export const KDF_MEMORY = 65536; // Memory for Argon2id (KB)
export const KDF_PARALLELISM = 4; // Parallelism for Argon2id
export const ENCRYPTION_ALGORITHM = 'AES-GCM';
export const AUTH_TAG_LENGTH = 128; // bits
export const JWT_TOKEN_KEY = 'jwtToken';
export const USER_INFO_KEY = 'userInfo';
export const SESSION_TIMEOUT_MINUTES = 5; // Minutes of inactivity before logout
export const DEFAULT_MASTER_PASSWORD_CHANGE_LOADING_MESSAGE = "Processing... Please wait. Your vault data is being re-encrypted with your new Master Password. Do NOT close this window.";