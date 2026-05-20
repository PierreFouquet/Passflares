// public/js/pages/settings.js — appearance + account actions.

import { cloneTemplate, showLoading, hideLoading } from '../ui.js';
import { getPrefs, setPrefs, ALLOWED } from '../prefs.js';
import { snack } from '../snackbar.js';
import { confirmDialog, openDialog } from '../dialog.js';
import { getUserInfo, clearSession } from '../session.js';
import { reset as resetState, getKey, getVaults } from '../state.js';
import { deleteAccount, updateMasterPassword, loadEncryptedVaultData, saveEncryptedVaultData, getVaults as apiGetVaults } from '../api.js';
import { deriveKey, encryptData, decryptData } from '../crypto.js';
import { checkPasswordStrength, generateSalt, uint8ArrayToHexString } from '../utils.js';
import { storeSession, getSessionToken } from '../session.js';

export function renderSettingsPage({ mount }) {
    mount.appendChild(cloneTemplate('tpl-page-settings'));

    const userInfo = getUserInfo();
    const emailSlot = mount.querySelector('[data-account-email]');
    if (emailSlot && userInfo?.email) emailSlot.textContent = userInfo.email;

    // Initialise pref controls
    const prefs = getPrefs();
    ['theme', 'density', 'shape'].forEach(field => {
        mount.querySelectorAll(`[data-pref-group="${field}"] input`).forEach(input => {
            input.checked = input.value === prefs[field];
            input.addEventListener('change', () => {
                if (input.checked && ALLOWED[field].includes(input.value)) {
                    setPrefs({ [field]: input.value });
                    snack.success(`${labelOf(field)} updated.`);
                }
            });
        });
    });

    mount.querySelectorAll('[data-pref-group="accent"] [data-accent-value]').forEach(btn => {
        btn.classList.toggle('is-active', btn.dataset.accentValue === prefs.accent);
        btn.addEventListener('click', () => {
            mount.querySelectorAll('[data-pref-group="accent"] [data-accent-value]')
                .forEach(b => b.classList.remove('is-active'));
            btn.classList.add('is-active');
            setPrefs({ accent: btn.dataset.accentValue });
            snack.success('Accent updated.');
        });
    });

    // Account action buttons
    mount.querySelector('[data-action="change-password"]').addEventListener('click', openChangePasswordDialog);
    mount.querySelector('[data-action="export"]').addEventListener('click', handleExport);
    mount.querySelector('[data-action="delete-account"]').addEventListener('click', openDeleteAccountDialog);
}

function labelOf(field) {
    return { theme: 'Theme', density: 'Density', shape: 'Shape', accent: 'Accent' }[field] ?? field;
}

// ── Change master password ─────────────────────
function openChangePasswordDialog() {
    const body = document.createElement('div');
    body.innerHTML = `
        <p class="text-muted">All your vault data will be re-encrypted under the new password. Do not close this window.</p>
        <div class="field password-field">
            <input type="password" id="old-mp" placeholder=" " required>
            <label for="old-mp">Current master password</label>
        </div>
        <div class="field password-field">
            <input type="password" id="new-mp" placeholder=" " required>
            <label for="new-mp">New master password</label>
        </div>
        <div class="password-meter" data-score="0">
            <div class="password-meter__bar"><div class="password-meter__fill"></div></div>
            <span id="new-mp-strength">Enter a strong master password</span>
        </div>
        <div class="field password-field">
            <input type="password" id="confirm-mp" placeholder=" " required>
            <label for="confirm-mp">Confirm new master password</label>
        </div>
    `;
    const newPwdEl = body.querySelector('#new-mp');
    const meter = body.querySelector('.password-meter');
    const meterText = body.querySelector('#new-mp-strength');
    newPwdEl.addEventListener('input', () => {
        const { score, strength, meetsMinRequirements } = checkPasswordStrength(newPwdEl.value);
        meter.dataset.score = String(Math.max(0, Math.min(4, Math.round(score * 4 / 6))));
        meterText.textContent = newPwdEl.value
            ? `${strength}${meetsMinRequirements ? '' : ' — needs 12+ chars, mixed categories'}`
            : 'Enter a strong master password';
    });

    openDialog({
        title: 'Change master password',
        body,
        actions: [
            { label: 'Cancel', variant: 'text' },
            {
                label: 'Change password',
                variant: 'filled',
                closeOnClick: false,
                onClick: async ({ close }) => {
                    const old = body.querySelector('#old-mp').value;
                    const next = body.querySelector('#new-mp').value;
                    const confirmV = body.querySelector('#confirm-mp').value;
                    if (next !== confirmV) { snack.error('New passwords do not match.'); return; }
                    const s = checkPasswordStrength(next);
                    if (s.score < 3 || !s.meetsMinRequirements) {
                        snack.error('New password is too weak.');
                        return;
                    }
                    const userInfo = getUserInfo();
                    if (!userInfo?.userId) { snack.error('Please sign in again.'); return; }

                    showLoading('Re-encrypting all vault data… do not close this window.');
                    try {
                        // 1. Derive old key from current salt
                        const oldKey = await deriveKey(old, userInfo.encryptionSalt);
                        // 2. Pull and decrypt every vault
                        const vaults = await apiGetVaults();
                        const decryptedVaults = [];
                        for (const v of vaults) {
                            const raw = await loadEncryptedVaultData(v.id);
                            const data = raw?.encryptedData ? await decryptData(raw.encryptedData, oldKey) : [];
                            decryptedVaults.push({ id: v.id, data });
                        }
                        // 3. Generate new salt + key
                        const newSalt = generateSalt();
                        const newSaltHex = uint8ArrayToHexString(newSalt);
                        const newKey = await deriveKey(next, newSaltHex);
                        // 4. Re-encrypt + upload
                        for (const v of decryptedVaults) {
                            const enc = await encryptData(v.data, newKey);
                            await saveEncryptedVaultData(v.id, enc);
                        }
                        // 5. Tell the server about the new password + salt
                        await updateMasterPassword(userInfo.userId, old, next, newSaltHex);
                        // 6. Update local session
                        storeSession(getSessionToken(), { ...userInfo, encryptionSalt: newSaltHex });
                        snack.success('Master password changed successfully.');
                        close();
                    } catch (err) {
                        console.error('Master password change failed:', err);
                        snack.error(err.message ?? 'Failed to change master password.');
                    } finally {
                        hideLoading();
                    }
                }
            }
        ]
    });
}

// ── Export ─────────────────────────────────────
async function handleExport() {
    if (!getKey()) { snack.error('No encryption key available — sign in again.'); return; }
    showLoading('Exporting vault data…');
    try {
        const vaults = await apiGetVaults();
        const exportData = { metadata: [], encryptedVaults: {} };
        for (const v of vaults) {
            const raw = await loadEncryptedVaultData(v.id);
            exportData.encryptedVaults[v.id] = raw?.encryptedData ?? null;
            exportData.metadata.push({
                id: v.id, name: v.name, description: v.description,
                owner_id: v.owner_id, owner_type: v.owner_type,
                r2_object_key: v.r2_object_key, current_key_version: v.current_key_version
            });
        }
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `passflares-export-${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        snack.success('Encrypted export downloaded.');
    } catch (err) {
        snack.error(err.message ?? 'Export failed.');
    } finally {
        hideLoading();
    }
}

// ── Delete account ─────────────────────────────
function openDeleteAccountDialog() {
    const body = document.createElement('div');
    body.innerHTML = `
        <p style="color: var(--color-danger);"><strong>This is permanent.</strong> Your account and all personal vault data will be deleted. Organisation-owned vaults remain.</p>
        <div class="field password-field">
            <input type="password" id="delete-mp" placeholder=" " required>
            <label for="delete-mp">Enter your master password to confirm</label>
        </div>
    `;
    openDialog({
        title: 'Delete account',
        variant: 'danger',
        body,
        actions: [
            { label: 'Cancel', variant: 'text' },
            {
                label: 'Delete my account',
                variant: 'danger',
                closeOnClick: false,
                onClick: async ({ close }) => {
                    const mp = body.querySelector('#delete-mp').value;
                    const userInfo = getUserInfo();
                    if (!userInfo?.userId) { snack.error('Please sign in again.'); return; }
                    showLoading('Deleting account…');
                    try {
                        await deleteAccount(userInfo.userId, mp);
                        clearSession();
                        resetState();
                        snack.info('Account deleted.');
                        close();
                        window.location.reload();
                    } catch (err) {
                        snack.error(err.message ?? 'Failed to delete account.');
                    } finally {
                        hideLoading();
                    }
                }
            }
        ]
    });
}
