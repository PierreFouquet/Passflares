// public/js/state.js — shared app state.
// Holds the live encryption key (in-memory only, never persisted) and
// caches of vaults + organisations to avoid re-fetching on every page swap.

const state = {
    encryptionKey: null,
    vaults: [],
    organizations: [],
    // Map<vaultId, { metadata, entries }> for vaults we've decrypted this session
    decryptedVaults: new Map(),
    currentVaultId: null
};

export function getKey() { return state.encryptionKey; }
export function setKey(key) { state.encryptionKey = key; }
export function hasKey() { return state.encryptionKey !== null; }

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
    state.encryptionKey = null;
    state.vaults = [];
    state.organizations = [];
    state.decryptedVaults.clear();
    state.currentVaultId = null;
}
