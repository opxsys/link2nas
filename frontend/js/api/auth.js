import { request } from "./request.js";

// V2 setup/auth
export function getSetupStatus() {
  return request("/api/v2/setup/status", { method: "GET" });
}

export function getPublicAppInfo() {
  return request("/api/v2/public/app-info", { method: "GET" });
}

export function createFirstAdmin(payload) {
  return request("/api/v2/setup/first-admin", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function login(payload) {
  return request("/api/v2/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function logout() {
  return request("/api/v2/auth/logout", { method: "POST" });
}

// V2 current user
export function getMe() {
  return request("/api/v2/me", { method: "GET" });
}

export function updateMe(payload) {
  return request("/api/v2/me", {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function changeMyPassword(payload) {
  return request("/api/v2/me/password", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function requestEmailVerification() {
  return request("/api/v2/me/request-email-verification", {
    method: "POST",
  });
}

export function getMyIntegrationSettings() {
  return request("/api/v2/me/integration-settings", { method: "GET" });
}

export function saveMyIntegrationSettings(payload) {
  return request("/api/v2/me/integration-settings", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function listUserApiKeys() {
  return request("/api/v2/me/api-keys", { method: "GET" });
}

export function createUserApiKey(payload) {
  return request("/api/v2/me/api-keys", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function revokeUserApiKey(keyId) {
  return request(`/api/v2/me/api-keys/${encodeURIComponent(keyId)}/revoke`, {
    method: "POST",
  });
}

export function deleteUserApiKey(keyId) {
  return request(`/api/v2/me/api-keys/${encodeURIComponent(keyId)}`, {
    method: "DELETE",
  });
}

// V2 public account tokens
export function getPublicTokenStatus(token) {
  return request(`/api/v2/public/tokens/${encodeURIComponent(token)}/status`, {
    method: "GET",
  });
}

export function acceptInvitation(token, password) {
  return request("/api/v2/public/invitations/accept", {
    method: "POST",
    body: JSON.stringify({
      token,
      password,
    }),
  });
}

export function confirmPasswordReset(token, password) {
  return request("/api/v2/public/password-reset/confirm", {
    method: "POST",
    body: JSON.stringify({
      token,
      password,
    }),
  });
}

export function requestMagicLogin(email) {
  return request("/api/v2/public/magic-login/request", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}

export function confirmMagicLogin(token) {
  return request("/api/v2/public/magic-login/confirm", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}

export function confirmEmailVerification(token) {
  return request("/api/v2/public/email-verification/confirm", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}
