// public/js/session.js

import { JWT_TOKEN_KEY, USER_INFO_KEY, SESSION_TIMEOUT_MINUTES } from './constants.js';

let sessionTimeoutTimer = null;
let inactivityTimer = null;
let resetTimerFunction = null; // Store reference to reset function

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
    stopInactivityTimer(); // Clear inactivity timer and event listeners
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

    resetTimerFunction = () => {
        clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(logoutUser, timeoutDuration);
    };

    // Initialize the timer
    resetTimerFunction();

    // Attach event listeners to reset the timer on user activity
    window.addEventListener('mousemove', resetTimerFunction);
    window.addEventListener('keydown', resetTimerFunction);
    window.addEventListener('click', resetTimerFunction);
    window.addEventListener('scroll', resetTimerFunction);

    console.log(`Inactivity timer started for ${SESSION_TIMEOUT_MINUTES} minutes.`);
}

export function stopInactivityTimer() {
    clearTimeout(inactivityTimer);
    if (resetTimerFunction) {
        window.removeEventListener('mousemove', resetTimerFunction);
        window.removeEventListener('keydown', resetTimerFunction);
        window.removeEventListener('click', resetTimerFunction);
        window.removeEventListener('scroll', resetTimerFunction);
        resetTimerFunction = null;
    }
    inactivityTimer = null;
    console.log("Inactivity timer stopped.");
}

// Helper to reset timer
function resetInactivityTimer() {
    stopInactivityTimer();
    startInactivityTimer();
}

// Function to check if user is logged in
export function isLoggedIn() {
    return !!getSessionToken() && !!getUserInfo();
}