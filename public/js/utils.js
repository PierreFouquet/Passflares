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
    const minLength = 12;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);
    
    let score = 0;
    if (password.length >= minLength) score += 2;
    if (hasLower) score++;
    if (hasUpper) score++;
    if (hasNumber) score++;
    if (hasSpecial) score++;
    
    let strength = "Very Weak";
    let color = "red";
    if (score >= 6) { strength = "Excellent"; color = "lime"; }
    else if (score >= 5) { strength = "Strong"; color = "lightgreen"; }
    else if (score >= 3) { strength = "Moderate"; color = "orange"; }
    else if (score >= 1) { strength = "Weak"; color = "yellow"; }

    const meetsMinRequirements = password.length >= minLength && 
                               hasLower && 
                               hasUpper && 
                               hasNumber && 
                               hasSpecial;
    
    return { 
        score, 
        strength, 
        color,
        meetsMinRequirements
    };
}

// Cryptographically-secure unbiased integer in [0, max). Uses rejection
// sampling on `crypto.getRandomValues` to avoid the modulo bias that
// `randomU32() % max` would introduce when max is not a power of two.
function secureRandomInt(max) {
    if (max <= 0 || max > 0x100000000) {
        throw new RangeError(`secureRandomInt: max out of range (got ${max})`);
    }
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    let n;
    do {
        crypto.getRandomValues(buf);
        n = buf[0];
    } while (n >= limit);
    return n % max;
}

export function generateRandomPassword(length = 16) {
    // Minimum length must accommodate one of each required character class.
    if (length < 4) length = 4;

    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers   = "0123456789";
    const symbols   = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~";
    const allChars  = lowercase + uppercase + numbers + symbols;

    // Seed with one guaranteed character from each class so the password
    // always meets the strength meter's class requirements.
    const chars = [
        lowercase[secureRandomInt(lowercase.length)],
        uppercase[secureRandomInt(uppercase.length)],
        numbers  [secureRandomInt(numbers.length)],
        symbols  [secureRandomInt(symbols.length)]
    ];
    for (let i = 4; i < length; i++) {
        chars.push(allChars[secureRandomInt(allChars.length)]);
    }

    // Fisher-Yates shuffle so the guaranteed-class characters aren't pinned
    // at the start. `Array.prototype.sort(() => Math.random() - 0.5)` is
    // both biased AND non-CSPRNG, so the security gain from above would be
    // lost otherwise.
    for (let i = chars.length - 1; i > 0; i--) {
        const j = secureRandomInt(i + 1);
        const tmp = chars[i];
        chars[i] = chars[j];
        chars[j] = tmp;
    }
    return chars.join('');
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
