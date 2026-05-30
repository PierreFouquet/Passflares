// public/js/pages/settings.js — appearance + account actions.

import { cloneTemplate, showLoading, hideLoading } from '../ui.js';
import { getPrefs, setPrefs, ALLOWED } from '../prefs.js';
import { snack } from '../snackbar.js';
import { confirmDialog, openDialog } from '../dialog.js';
import { getUserInfo, clearSession } from '../session.js';
import { reset as resetState, getKey, getVaults } from '../state.js';
import { deleteAccount, updateMasterPassword, loadEncryptedVaultData, saveEncryptedVaultData, getVaults as apiGetVaults } from '../api.js';
import { getTotpStatus, enrollTotp, enableTotp, disableTotp, regenerateRecoveryCodes } from '../api.js';
import { deriveKey, encryptData, decryptData } from '../crypto.js';
import { checkPasswordStrength, generateSalt, uint8ArrayToHexString } from '../utils.js';
import { storeSession, getSessionToken } from '../session.js';
import { copyToClipboard } from '../clipboard.js';

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

    // Two-factor authentication section
    initTotpSection(mount);
}

// ── Two-factor authentication ──────────────────────
async function initTotpSection(mount) {
    const section = mount.querySelector('[data-totp-section]');
    if (!section) return;
    const statusEl = section.querySelector('[data-totp-status]');
    const enableBtn = section.querySelector('[data-action="totp-enable"]');
    const changeBtn = section.querySelector('[data-action="totp-change"]');
    const regenBtn = section.querySelector('[data-action="totp-regenerate"]');
    const disableBtn = section.querySelector('[data-action="totp-disable"]');

    const setBusy = (busy) => {
        [enableBtn, changeBtn, regenBtn, disableBtn].forEach(b => { if (b) b.disabled = busy; });
    };

    async function refresh() {
        setBusy(true);
        try {
            const { enabled, remainingRecoveryCodes } = await getTotpStatus();
            if (statusEl) {
                statusEl.textContent = enabled
                    ? `Enabled — ${remainingRecoveryCodes} recovery code${remainingRecoveryCodes === 1 ? '' : 's'} remaining.`
                    : 'Disabled. Add an authenticator app for stronger account security.';
            }
            enableBtn?.classList.toggle('hidden', enabled);
            changeBtn?.classList.toggle('hidden', !enabled);
            regenBtn?.classList.toggle('hidden', !enabled);
            disableBtn?.classList.toggle('hidden', !enabled);
        } catch (err) {
            if (statusEl) statusEl.textContent = 'Could not load 2FA status.';
        } finally {
            setBusy(false);
        }
    }

    enableBtn?.addEventListener('click', () => openEnrollDialog(false, refresh));
    changeBtn?.addEventListener('click', () => openEnrollDialog(true, refresh));
    regenBtn?.addEventListener('click', () => openRegenerateDialog(refresh));
    disableBtn?.addEventListener('click', () => openDisableDialog(refresh));

    await refresh();
}

// Renders a list of recovery codes into a container with Copy + Download, gated
// behind an acknowledgement checkbox that enables the dialog's close button.
function renderRecoveryCodes(codes, { onAcknowledge } = {}) {
    const wrap = document.createElement('div');

    const warn = document.createElement('p');
    warn.className = 'text-muted';
    warn.textContent = 'Save these recovery codes somewhere safe. Each works once and they will not be shown again.';

    const list = document.createElement('ul');
    list.className = 'recovery-code-list';
    codes.forEach(code => {
        const li = document.createElement('li');
        li.className = 'recovery-code text-mono';
        li.textContent = code;
        list.appendChild(li);
    });

    const actions = document.createElement('div');
    actions.className = 'row row-wrap';
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'btn btn--tonal btn--sm';
    copyBtn.textContent = 'Copy codes';
    copyBtn.addEventListener('click', () => copyToClipboard(codes.join('\n'), { successMessage: 'Recovery codes copied.' }));
    const dlBtn = document.createElement('button');
    dlBtn.type = 'button';
    dlBtn.className = 'btn btn--tonal btn--sm';
    dlBtn.textContent = 'Download .txt';
    dlBtn.addEventListener('click', () => {
        const blob = new Blob([codes.join('\n') + '\n'], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `passflares-recovery-codes-${new Date().toISOString().slice(0, 10)}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });
    actions.append(copyBtn, dlBtn);

    const ackLabel = document.createElement('label');
    ackLabel.className = 'checkbox-row';
    const ack = document.createElement('input');
    ack.type = 'checkbox';
    const ackText = document.createElement('span');
    ackText.textContent = 'I have saved my recovery codes';
    ackLabel.append(ack, ackText);
    ack.addEventListener('change', () => onAcknowledge?.(ack.checked));

    wrap.append(warn, list, actions, ackLabel);
    return wrap;
}

// Enrollment (first-time enable) and change-authenticator share the QR → verify
// flow; `isChange` adds the master-password + current-code re-auth step.
function openEnrollDialog(isChange, onDone) {
    const body = document.createElement('div');

    let reauthInputs = null;
    if (isChange) {
        const intro = document.createElement('p');
        intro.className = 'text-muted';
        intro.textContent = 'Confirm it\'s you, then scan the new QR code.';
        const pwField = document.createElement('div');
        pwField.className = 'field password-field';
        const pw = document.createElement('input');
        pw.type = 'password'; pw.id = 'totp-reauth-pw'; pw.setAttribute('placeholder', ' ');
        const pwLabel = document.createElement('label');
        pwLabel.setAttribute('for', 'totp-reauth-pw'); pwLabel.textContent = 'Master password';
        pwField.append(pw, pwLabel);
        const codeField = document.createElement('div');
        codeField.className = 'field';
        const code = document.createElement('input');
        code.type = 'text'; code.id = 'totp-reauth-code'; code.setAttribute('placeholder', ' ');
        code.setAttribute('inputmode', 'numeric'); code.setAttribute('autocomplete', 'one-time-code');
        const codeLabel = document.createElement('label');
        codeLabel.setAttribute('for', 'totp-reauth-code'); codeLabel.textContent = 'Current code or recovery code';
        codeField.append(code, codeLabel);
        body.append(intro, pwField, codeField);
        reauthInputs = { pw, code };
    } else {
        const intro = document.createElement('p');
        intro.className = 'text-muted';
        intro.textContent = 'Scan this QR code with your authenticator app, then enter the 6-digit code to confirm.';
        body.appendChild(intro);
    }

    const qrSlot = document.createElement('div');
    qrSlot.className = 'totp-qr-slot';
    body.appendChild(qrSlot);

    const secretLine = document.createElement('p');
    secretLine.className = 'text-muted text-mono totp-secret hidden';
    body.appendChild(secretLine);

    const verifyField = document.createElement('div');
    verifyField.className = 'field hidden';
    const verifyInput = document.createElement('input');
    verifyInput.type = 'text'; verifyInput.id = 'totp-verify'; verifyInput.setAttribute('placeholder', ' ');
    verifyInput.setAttribute('inputmode', 'numeric'); verifyInput.setAttribute('autocomplete', 'one-time-code');
    verifyInput.maxLength = 6;
    const verifyLabel = document.createElement('label');
    verifyLabel.setAttribute('for', 'totp-verify'); verifyLabel.textContent = 'Verification code';
    verifyField.append(verifyInput, verifyLabel);
    body.appendChild(verifyField);

    let pendingStarted = false;

    const startEnroll = async () => {
        showLoading('Setting up…');
        try {
            const reauth = isChange
                ? { masterPassword: reauthInputs.pw.value, code: reauthInputs.code.value.trim() }
                : null;
            const { secret, qrDataUri } = await enrollTotp(reauth);
            const img = document.createElement('img');
            img.alt = 'Authenticator QR code';
            img.className = 'totp-qr';
            img.src = qrDataUri;
            qrSlot.replaceChildren(img);
            secretLine.textContent = `Secret: ${secret}`;
            secretLine.classList.remove('hidden');
            verifyField.classList.remove('hidden');
            if (reauthInputs) { reauthInputs.pw.disabled = true; reauthInputs.code.disabled = true; }
            verifyInput.focus();
            pendingStarted = true;
            return true;
        } catch (err) {
            snack.error(err.message ?? 'Could not start 2FA setup.');
            return false;
        } finally {
            hideLoading();
        }
    };

    const verify = async ({ close }) => {
        if (!pendingStarted) { await startEnroll(); return; }
        const code = verifyInput.value.trim();
        if (!code) { snack.error('Enter the code from your app.'); return; }
        showLoading('Verifying…');
        try {
            const resp = await enableTotp(code);
            if (resp?.recoveryCodes) {
                // First-time enable — show recovery codes once, gate the close.
                const verifyBtn = document.querySelector('.dialog__actions .btn--filled');
                let acked = false;
                body.replaceChildren(renderRecoveryCodes(resp.recoveryCodes, {
                    onAcknowledge: (checked) => { acked = checked; if (verifyBtn) verifyBtn.disabled = !checked; }
                }));
                if (verifyBtn) { verifyBtn.textContent = 'Done'; verifyBtn.disabled = true; }
                // Swap the action to a plain close on next click.
                pendingStarted = 'codes-shown';
                snack.success('Two-factor authentication enabled.');
                onDone?.();
            } else {
                snack.success('Authenticator updated.');
                onDone?.();
                close();
            }
        } catch (err) {
            snack.error(err.message ?? 'That code was not valid.');
            verifyInput.value = '';
            verifyInput.focus();
        } finally {
            hideLoading();
        }
    };

    openDialog({
        title: isChange ? 'Change authenticator' : 'Enable two-factor authentication',
        body,
        actions: [
            { label: 'Cancel', variant: 'text' },
            {
                label: isChange ? 'Confirm' : 'Continue',
                variant: 'filled',
                closeOnClick: false,
                onClick: (ctx) => {
                    if (pendingStarted === 'codes-shown') { ctx.close(); return; }
                    return verify(ctx);
                }
            }
        ]
    });
}

function openRegenerateDialog(onDone) {
    const body = document.createElement('div');
    const intro = document.createElement('p');
    intro.className = 'text-muted';
    intro.textContent = 'Generating new recovery codes invalidates your old ones. Confirm your master password.';
    const pwField = document.createElement('div');
    pwField.className = 'field password-field';
    const pw = document.createElement('input');
    pw.type = 'password'; pw.id = 'regen-pw'; pw.setAttribute('placeholder', ' ');
    const pwLabel = document.createElement('label');
    pwLabel.setAttribute('for', 'regen-pw'); pwLabel.textContent = 'Master password';
    pwField.append(pw, pwLabel);
    body.append(intro, pwField);

    let shown = false;
    openDialog({
        title: 'Regenerate recovery codes',
        body,
        actions: [
            { label: 'Cancel', variant: 'text' },
            {
                label: 'Generate',
                variant: 'filled',
                closeOnClick: false,
                onClick: async ({ close }) => {
                    if (shown) { close(); return; }
                    if (!pw.value) { snack.error('Enter your master password.'); return; }
                    showLoading('Generating…');
                    try {
                        const { recoveryCodes } = await regenerateRecoveryCodes(pw.value);
                        const btn = document.querySelector('.dialog__actions .btn--filled');
                        body.replaceChildren(renderRecoveryCodes(recoveryCodes, {
                            onAcknowledge: (checked) => { if (btn) btn.disabled = !checked; }
                        }));
                        if (btn) { btn.textContent = 'Done'; btn.disabled = true; }
                        shown = true;
                        onDone?.();
                        snack.success('New recovery codes generated.');
                    } catch (err) {
                        snack.error(err.message ?? 'Could not regenerate codes.');
                    } finally {
                        hideLoading();
                    }
                }
            }
        ]
    });
}

function openDisableDialog(onDone) {
    const body = document.createElement('div');
    const intro = document.createElement('p');
    intro.className = 'text-muted';
    intro.textContent = 'Disabling 2FA removes your authenticator and recovery codes. Confirm your master password and a current code.';
    const pwField = document.createElement('div');
    pwField.className = 'field password-field';
    const pw = document.createElement('input');
    pw.type = 'password'; pw.id = 'disable-pw'; pw.setAttribute('placeholder', ' ');
    const pwLabel = document.createElement('label');
    pwLabel.setAttribute('for', 'disable-pw'); pwLabel.textContent = 'Master password';
    pwField.append(pw, pwLabel);
    const codeField = document.createElement('div');
    codeField.className = 'field';
    const code = document.createElement('input');
    code.type = 'text'; code.id = 'disable-code'; code.setAttribute('placeholder', ' ');
    code.setAttribute('inputmode', 'numeric'); code.setAttribute('autocomplete', 'one-time-code');
    const codeLabel = document.createElement('label');
    codeLabel.setAttribute('for', 'disable-code'); codeLabel.textContent = 'Current code or recovery code';
    codeField.append(code, codeLabel);
    body.append(intro, pwField, codeField);

    openDialog({
        title: 'Disable two-factor authentication',
        variant: 'danger',
        body,
        actions: [
            { label: 'Cancel', variant: 'text' },
            {
                label: 'Disable 2FA',
                variant: 'danger',
                closeOnClick: false,
                onClick: async ({ close }) => {
                    if (!pw.value || !code.value.trim()) { snack.error('Both fields are required.'); return; }
                    showLoading('Disabling…');
                    try {
                        await disableTotp(pw.value, code.value.trim());
                        snack.success('Two-factor authentication disabled.');
                        onDone?.();
                        close();
                    } catch (err) {
                        snack.error(err.message ?? 'Could not disable 2FA.');
                    } finally {
                        hideLoading();
                    }
                }
            }
        ]
    });
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
        <p class="text-danger"><strong>This is permanent.</strong> Your account and all personal vault data will be deleted. Organisation-owned vaults remain.</p>
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
