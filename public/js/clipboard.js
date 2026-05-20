// public/js/clipboard.js — snackbar-aware clipboard helper.

import { snack } from './snackbar.js';

export async function copyToClipboard(text, { successMessage = 'Copied to clipboard' } = {}) {
    if (text === null || text === undefined) return false;
    try {
        await navigator.clipboard.writeText(String(text));
        snack.success(successMessage);
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        snack.error('Could not copy to clipboard');
        return false;
    }
}
