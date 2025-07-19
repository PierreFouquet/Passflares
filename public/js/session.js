// public/js/session.js

import { JWT_TOKEN_KEY, USER_INFO_KEY, SESSION_TIMEOUT_MINUTES } from './constants.js';
import { showMessage, hideElement, showElement } from './ui.js';
import { loadVaults } from './main.js'; // Cyclic dependency, usually handle with events or central store

let sessionTimeoutTimer = null;
let inactivityTimer = null;

export function storeSession(token, user) {
    localStorage.setItem(JWT_TOKEN_KEY, token);
    localStorage.setItem(USER_INFO_KEY, JSON.stringify(user));
    resetInactivityTimer();
}

export function getSessionToken() {
    return localStorage.getItem(JWT_TOKEN_KEY);
}

export function getUserInfo() {
    const userInfo = localStorage.getItem(USER_INFO_KEY);
    return userInfo ? JSON.parse(userInfo) : null;
}

export function clearSession() {
    localStorage.removeItem(JWT_TOKEN_KEY);
    localStorage.removeItem(USER_INFO_KEY);
    clearTimeout(sessionTimeoutTimer);
    clearTimeout(inactivityTimer);
    sessionTimeoutTimer = null;
    inactivityTimer = null;
    console.log("Session cleared.");
}

export function getAuthHeaders() {
    const token = getSessionToken();
    if (!token) {
        throw new Error("No authentication token found. Please log in.");
    }
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
}

export function startInactivityTimer() {
    const timeoutDuration = SESSION_TIMEOUT_MINUTES * 60 * 1000; // Convert minutes to milliseconds

    const logoutUser = () => {
        clearSession();
        alert("You have been logged out due to inactivity.");
        window.location.reload(); // Simple refresh to return to login
    };

    const resetTimer = () => {
        clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(logoutUser, timeoutDuration);
    };

    // Initialize the timer
    resetTimer();

    // Attach event listeners to reset the timer on user activity
    window.addEventListener('mousemove', resetTimer);
    window.addEventListener('keydown', resetTimer);
    window.addEventListener('click', resetTimer);
    window.addEventListener('scroll', resetTimer);

    console.log(`Inactivity timer started for ${SESSION_TIMEOUT_MINUTES} minutes.`);
}

export function stopInactivityTimer() {
    clearTimeout(inactivityTimer);
    window.removeEventListener('mousemove', resetTimer); // Need to pass the exact function reference
    window.removeEventListener('keydown', resetTimer);
    window.removeEventListener('click', resetTimer);
    window.removeEventListener('scroll', resetTimer);
    inactivityTimer = null;
    console.log("Inactivity timer stopped.");
}

// Helper to reset timer; needs to be defined globally or passed
function resetInactivityTimer() {
    startInactivityTimer(); // Re-starts the timer
}

// Function to check if user is logged in
export function isLoggedIn() {
    return !!getSessionToken() && !!getUserInfo();
}
