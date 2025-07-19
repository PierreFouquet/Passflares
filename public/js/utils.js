// public/js/utils.js

import { KDF_SALT_LENGTH } from './constants.js';

export function uint8ArrayToHexString(uint8array) {
    return Array.from(uint8array)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

export function hexStringToUint8Array(hexString) {
    if (hexString.length % 2 !== 0) {
        throw new Error("Hex string must have an even number of characters.");
    }
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        bytes.push(parseInt(hexString.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
}

export function generateSalt(length = KDF_SALT_LENGTH) {
    const salt = new Uint8Array(length);
    crypto.getRandomValues(salt);
    return salt;
}

export function checkPasswordStrength(password) {
    let score = 0;
    if (password.length >= 10) score++;
    if (password.length >= 14) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[!@#$%^&*()-_=+[{]}\\|;:'",<.>/?`~]/.test(password)) score++;

    let strength = "Very Weak";
    let color = "red";
    if (score >= 6) { strength = "Excellent"; color = "lime"; }
    else if (score >= 5) { strength = "Strong"; color = "lightgreen"; }
    else if (score >= 3) { strength = "Moderate"; color = "orange"; }
    else if (score >= 1) { strength = "Weak"; color = "yellow"; }

    return { score, strength, color };
}

export function generateRandomPassword(length = 16) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~";
    let password = "";
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);

    for (let i = 0; i < length; i++) {
        password += charset[values[i] % charset.length];
    }
    return password;
}

export function searchVaultEntries(query, entries) {
    const lowerCaseQuery = query.toLowerCase();
    return entries.filter(entry =>
        entry.name.toLowerCase().includes(lowerCaseQuery) ||
        (entry.username && entry.username.toLowerCase().includes(lowerCaseQuery)) ||
        (entry.url && entry.url.toLowerCase().includes(lowerCaseQuery)) ||
        (entry.notes && entry.notes.toLowerCase().includes(lowerCaseQuery))
    );
}

export function copyToClipboard(text, targetButton) {
    navigator.clipboard.writeText(text).then(() => {
        const originalText = targetButton.textContent;
        targetButton.textContent = 'Copied!';
        setTimeout(() => {
            targetButton.textContent = originalText;
        }, 1000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}
