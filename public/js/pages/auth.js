// public/js/pages/auth.js — login + register flow.

import { registerUser, loginUser, verifyLogin2fa } from '../api.js';
import { deriveKey } from '../crypto.js';
import { storeSession } from '../session.js';
import { setKey } from '../state.js';
import { snack } from '../snackbar.js';
import { showLoading, hideLoading } from '../ui.js';
import { openDialog } from '../dialog.js';
import { checkPasswordStrength, generateSalt, uint8ArrayToHexString } from '../utils.js';

let onLoggedIn = null;

export function initAuthPage({ onLogin, prefillEmail, notice } = {}) {
    onLoggedIn = onLogin;

    const noticeEl = document.getElementById('auth-notice');
    if (noticeEl) {
        if (notice) {
            noticeEl.textContent = notice;
            noticeEl.classList.remove('hidden');
        } else {
            noticeEl.textContent = '';
            noticeEl.classList.add('hidden');
        }
    }
    if (prefillEmail) {
        const emailInput = document.getElementById('login-email');
        if (emailInput) emailInput.value = prefillEmail;
        document.getElementById('login-master-password')?.focus();
    }

    const tabs = document.querySelectorAll('.auth-tabs button[data-tab]');
    const panels = document.querySelectorAll('[data-tab-panel]');
    tabs.forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            tabs.forEach(b => {
                const active = b === btn;
                b.classList.toggle('is-active', active);
                b.setAttribute('aria-selected', active ? 'true' : 'false');
            });
            panels.forEach(p => p.classList.toggle('hidden', p.dataset.tabPanel !== tab));
        });
    });

    document.querySelectorAll('[data-toggle-password]').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = btn.parentElement.querySelector('input');
            if (!input) return;
            const showing = input.type === 'text';
            input.type = showing ? 'password' : 'text';
            btn.querySelector('.icon').textContent = showing ? 'visibility' : 'visibility_off';
        });
    });

    // Password strength meter (register form)
    const regPwd = document.getElementById('register-master-password');
    const meter  = document.querySelector('.password-meter');
    const meterText = document.getElementById('password-strength-text');
    if (regPwd && meter && meterText) {
        regPwd.addEventListener('input', () => {
            const { score, strength, meetsMinRequirements } = checkPasswordStrength(regPwd.value);
            const clamped = Math.max(0, Math.min(4, Math.round(score * 4 / 6)));
            meter.dataset.score = String(clamped);
            meterText.textContent = regPwd.value
                ? `${strength}${meetsMinRequirements ? '' : ' — needs mix of letters, numbers, symbols, 12+ chars'}`
                : 'Enter a strong master password';
        });
    }

    document.getElementById('login-form')?.addEventListener('submit', handleLogin);
    document.getElementById('register-form')?.addEventListener('submit', handleRegister);

    // Inject brand mark — parse via DOMParser instead of innerHTML so even a
    // same-origin SVG can't be executed as HTML if the file is ever swapped.
    fetch('img/logo.svg')
        .then(r => r.text())
        .then(svg => {
            const slot = document.querySelector('.auth-screen__brand');
            if (!slot) return;
            const doc = new DOMParser().parseFromString(svg, 'image/svg+xml');
            const node = doc.documentElement;
            if (node && node.nodeName.toLowerCase() === 'svg') {
                slot.replaceChildren(node);
            }
        })
        .catch(() => {});
}

function readTurnstileToken(form) {
    return form.querySelector('input[name="cf-turnstile-response"]')?.value || '';
}

function resetTurnstileWidgetIn(form) {
    // The Turnstile script exposes `window.turnstile.reset` once loaded; reset
    // so a failed submission can retry with a fresh challenge instead of
    // reusing an already-consumed token.
    const container = form.querySelector('.cf-turnstile');
    if (container && window.turnstile?.reset) {
        try { window.turnstile.reset(container); } catch {}
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const email = document.getElementById('register-email').value;
    const masterPassword = document.getElementById('register-master-password').value;
    const confirmPassword = document.getElementById('register-confirm-master-password').value;

    if (masterPassword !== confirmPassword) {
        snack.error('Master passwords do not match.');
        return;
    }
    const strength = checkPasswordStrength(masterPassword);
    if (strength.score < 3 || !strength.meetsMinRequirements) {
        snack.error('Please choose a stronger master password (12+ chars, mix of categories).');
        return;
    }

    const turnstileToken = readTurnstileToken(e.target);
    if (!turnstileToken) {
        snack.error('Please complete the CAPTCHA before creating your account.');
        return;
    }

    showLoading('Creating your account…');
    try {
        const encryptionSalt = generateSalt();
        await registerUser(email, masterPassword, uint8ArrayToHexString(encryptionSalt), turnstileToken);
        snack.success('Account created. You can now sign in.');
        e.target.reset();
        document.querySelector('.auth-tabs button[data-tab="login"]')?.click();
        document.getElementById('login-email').value = email;
    } catch (err) {
        console.error('Registration failed:', err);
        snack.error(err.message ?? 'Registration failed.');
        resetTurnstileWidgetIn(e.target);
    } finally {
        hideLoading();
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const masterPassword = document.getElementById('login-master-password').value;

    const turnstileToken = readTurnstileToken(e.target);
    if (!turnstileToken) {
        snack.error('Please complete the CAPTCHA before signing in.');
        return;
    }

    showLoading('Signing in…');
    try {
        const resp = await loginUser(email, masterPassword, turnstileToken);
        // Two-step login: the server withholds the session + encryption salt
        // until the second factor is verified. Keep the master password in
        // memory (closure) so we can derive the vault key after step 2.
        if (resp?.requires2FA) {
            hideLoading();
            promptSecondFactor(resp.tempToken, masterPassword, e.target);
            return;
        }
        await completeLogin(resp, masterPassword);
        e.target.reset();
    } catch (err) {
        console.error('Login failed:', err);
        snack.error(err.message ?? 'Could not sign in.');
        resetTurnstileWidgetIn(e.target);
    } finally {
        hideLoading();
    }
}

// Derives the vault key, stores the session, and hands off to the app. Shared
// by the single-step (no 2FA) and two-step (post-2FA) login paths.
async function completeLogin({ userId, email: userEmail, encryptionSalt, token }, masterPassword) {
    const key = await deriveKey(masterPassword, encryptionSalt);
    setKey(key);
    storeSession(token, { userId, email: userEmail, encryptionSalt });
    snack.success(`Welcome back, ${userEmail}`);
    onLoggedIn?.();
}

// Second-factor prompt. Built with DOM APIs (no innerHTML interpolation) so it
// satisfies the static XSS audit. Accepts a 6-digit TOTP code or a recovery
// code; the temp token proves the password step already passed.
function promptSecondFactor(tempToken, masterPassword, loginForm) {
    const body = document.createElement('div');

    const intro = document.createElement('p');
    intro.className = 'text-muted';
    intro.textContent = 'Enter the 6-digit code from your authenticator app.';

    const field = document.createElement('div');
    field.className = 'field';
    const input = document.createElement('input');
    input.type = 'text';
    input.id = 'totp-code';
    input.setAttribute('inputmode', 'numeric');
    input.setAttribute('autocomplete', 'one-time-code');
    input.setAttribute('placeholder', ' ');
    input.maxLength = 6;
    const label = document.createElement('label');
    label.setAttribute('for', 'totp-code');
    label.textContent = 'Authentication code';
    field.append(input, label);

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'btn btn--text btn--sm';
    toggle.textContent = 'Use a recovery code instead';

    let recoveryMode = false;
    toggle.addEventListener('click', () => {
        recoveryMode = !recoveryMode;
        if (recoveryMode) {
            intro.textContent = 'Enter one of your saved recovery codes.';
            label.textContent = 'Recovery code';
            input.setAttribute('inputmode', 'text');
            input.removeAttribute('maxLength');
            toggle.textContent = 'Use your authenticator app instead';
        } else {
            intro.textContent = 'Enter the 6-digit code from your authenticator app.';
            label.textContent = 'Authentication code';
            input.setAttribute('inputmode', 'numeric');
            input.maxLength = 6;
            toggle.textContent = 'Use a recovery code instead';
        }
        input.value = '';
        input.focus();
    });

    body.append(intro, field, toggle);

    const submit = async ({ close }) => {
        const code = input.value.trim();
        if (!code) { snack.error('Enter your code to continue.'); return; }
        showLoading('Verifying…');
        try {
            const resp = await verifyLogin2fa(tempToken, code);
            await completeLogin(resp, masterPassword);
            if (resp?.recoveryCodeUsed) {
                snack.warning(`Recovery code used. ${resp.remainingRecoveryCodes ?? 0} remaining.`);
            }
            loginForm?.reset();
            close();
        } catch (err) {
            console.error('2FA verification failed:', err);
            snack.error(err.message ?? 'Invalid code.');
            input.value = '';
            input.focus();
        } finally {
            hideLoading();
        }
    };

    const dlg = openDialog({
        title: 'Two-factor authentication',
        body,
        actions: [
            { label: 'Cancel', variant: 'text' },
            {
                label: 'Verify',
                variant: 'filled',
                closeOnClick: false,
                onClick: submit
            }
        ]
    });

    input.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' && dlg) { ev.preventDefault(); submit({ close: dlg.close }); }
    });
}
