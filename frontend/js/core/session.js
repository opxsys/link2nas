import { state } from "../state.js";

const TOKEN_KEY = "link2nas_token";
const DEFAULT_SESSION_INACTIVITY_MINUTES = 30;

let inactivityTimer;

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

function getSessionInactivityMinutes() {
  const raw = Number(state.currentUser?.session_inactivity_minutes);
  if (Number.isFinite(raw) && raw >= 5) return raw;
  return DEFAULT_SESSION_INACTIVITY_MINUTES;
}

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  const minutes = getSessionInactivityMinutes();
  inactivityTimer = setTimeout(() => {
    clearToken();
    location.reload();
  }, minutes * 60 * 1000);
}

export function startInactivityWatch() {
  ["click", "mousemove", "keydown"].forEach((eventName) => {
    document.addEventListener(eventName, resetInactivityTimer);
  });
  resetInactivityTimer();
}
