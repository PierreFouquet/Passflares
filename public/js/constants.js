// public/js/constants.js

export const API_BASE_URL = '/api'; // Proxy via Cloudflare Pages rewrites
export const KDF_SALT_LENGTH = 16; // bytes
export const AES_IV_LENGTH = 12; // bytes (for GCM)
// Legacy (auth_version 1) client KDF. PBKDF2-SHA256 is memory-less and so cheap
// to attack on GPUs; it survives only to decrypt vaults belonging to accounts
// that have not yet completed the auth_version 2 upgrade.
export const KDF_ITERATIONS = 600000;

// auth_version 2 client KDF. Argon2id is memory-hard, which is the actual
// cracking-resistance win over PBKDF2. m/t/p are OWASP's first-choice profile
// (m=46 MiB, t=1, p=1); measured ~550 ms in Node and ~1-1.5 s in-browser, which
// is why it runs in a Web Worker (public/js/kdf-worker.js) rather than on the UI
// thread. Stored per-user in D1 (users.kdf_params) so these can be raised later
// without locking anyone out of an account enrolled under the old numbers.
export const ARGON2_PARAMS = { m: 47104, t: 1, p: 1, len: 32 };

// HKDF domain separation. masterKey is never used directly as a key: the auth
// secret that reaches the server and the KEK that never leaves the browser are
// independent outputs, so learning one does not yield the other. Changing these
// strings invalidates every existing account — they are part of the wire format.
export const HKDF_INFO_AUTH = 'passflares:auth:v2';
export const HKDF_INFO_KEK = 'passflares:kek:v2';
export const HKDF_INFO_VAULT_SHARE = 'passflares:vaultshare:v2';

export const ENCRYPTION_ALGORITHM = 'AES-GCM';
export const AUTH_TAG_LENGTH = 128; // bits
export const JWT_TOKEN_KEY = 'jwtToken';
export const USER_INFO_KEY = 'userInfo';
export const SESSION_TIMEOUT_MINUTES = 5; // Minutes of inactivity before logout
export const DEFAULT_MASTER_PASSWORD_CHANGE_LOADING_MESSAGE = "Processing... Please wait. Your vault data is being re-encrypted with your new Master Password. Do NOT close this window.";