// public/js/state.js — shared app state.
//
// Holds the live key material (in-memory only, never persisted) and caches of
// vaults + organisations to avoid re-fetching on every page swap.
//
// Under the key hierarchy there is no longer a single "the encryption key".
// A session holds:
//   privateKey — the user's P-256 private key, unwrapped from user_keys at login
//   vaultKeys  — per-vault AES keys, unwrapped from vault_key_shares on demand
//   legacyKey  — the old PBKDF2 key, present only while pre-upgrade organisation
//                vaults remain (see legacyVaultsPending); used to rescue them
//
// None of these survive a reload. That is deliberate: the KEK that would unwrap
// privateKey only exists while the password is in memory.

const state = {
    privateKey: null,
    vaultKeys: new Map(),
    legacyKey: null,
    vaults: [],
    organizations: [],
    // Map<vaultId, { metadata, entries }> for vaults we've decrypted this session
    decryptedVaults: new Map(),
    currentVaultId: null
};

export function getPrivateKey() { return state.privateKey; }
export function setPrivateKey(key) { state.privateKey = key; }
export function hasPrivateKey() { return state.privateKey !== null; }

/** The AES key for one vault, once its share has been unwrapped. */
export function getVaultKey(vaultId) { return state.vaultKeys.get(vaultId) ?? null; }
export function setVaultKey(vaultId, key) { state.vaultKeys.set(vaultId, key); }
export function hasVaultKey(vaultId) { return state.vaultKeys.has(vaultId); }
export function forgetVaultKey(vaultId) {
    state.vaultKeys.delete(vaultId);
    state.decryptedVaults.delete(vaultId);
}

/**
 * The auth_version 1 PBKDF2 key. Only set when the account still owns
 * organisation vaults holding pre-upgrade ciphertext — it is the only key that
 * can decrypt them, and only their creator ever had it (#69).
 */
export function getLegacyKey() { return state.legacyKey; }
export function setLegacyKey(key) { state.legacyKey = key; }

export function getVaults() { return state.vaults; }
export function setVaults(v) { state.vaults = v; }

export function getOrgs() { return state.organizations; }
export function setOrgs(o) { state.organizations = o; }

export function setDecryptedVault(vaultId, payload) {
    state.decryptedVaults.set(vaultId, payload);
}
export function getDecryptedVault(vaultId) {
    return state.decryptedVaults.get(vaultId);
}
export function clearDecryptedVaults() {
    state.decryptedVaults.clear();
}

export function setCurrentVault(id) { state.currentVaultId = id; }
export function getCurrentVault() { return state.currentVaultId; }

export function getAllDecryptedEntries() {
    const out = [];
    for (const { metadata, entries } of state.decryptedVaults.values()) {
        for (const entry of entries) {
            out.push({ entry, vault: metadata });
        }
    }
    return out;
}

export function reset() {
    state.privateKey = null;
    state.vaultKeys.clear();
    state.legacyKey = null;
    state.vaults = [];
    state.organizations = [];
    state.decryptedVaults.clear();
    state.currentVaultId = null;
}
