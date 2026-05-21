import { request } from "./request.js";

// V2 admin users
export function listUsers() {
  return request("/api/v2/admin/users", { method: "GET" });
}

export function createUser(payload) {
  return request("/api/v2/admin/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateUser(userId, payload) {
  return request(`/api/v2/admin/users/${userId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function disableUser(userId) {
  return request(`/api/v2/admin/users/${userId}/disable`, {
    method: "POST",
  });
}

export function enableUser(userId) {
  return request(`/api/v2/admin/users/${userId}/enable`, {
    method: "POST",
  });
}

export function verifyUserEmail(userId) {
  return request(`/api/v2/admin/users/${userId}/verify-email`, {
    method: "POST",
  });
}

export function resetUserPassword(userId, password) {
  return request(`/api/v2/admin/users/${userId}/reset-password`, {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export function createUserInvitation(userId) {
  return request(`/api/v2/admin/users/${userId}/invitation`, {
    method: "POST",
  });
}

export function createUserPasswordResetLink(userId) {
  return request(`/api/v2/admin/users/${userId}/password-reset-link`, {
    method: "POST",
  });
}

export function sendUserInvitationEmail(userId) {
  return request(`/api/v2/admin/users/${userId}/invitation/email`, {
    method: "POST",
  });
}

export function sendUserPasswordResetEmail(userId) {
  return request(`/api/v2/admin/users/${userId}/password-reset-link/email`, {
    method: "POST",
  });
}

export function deleteUser(userId) {
  return request(`/api/v2/admin/users/${userId}`, {
    method: "DELETE",
  });
}
