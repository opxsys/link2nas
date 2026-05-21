import { ApiError, request } from "./request.js";
import { normalizeProviderRef, normalizeDestinationRef } from "./normalize.js";

export { ApiError };
export * from "./auth.js";
export * from "./system.js";
export * from "./jobs.js";

// V2 providers
export function listProviders() {
  return request("/api/v2/providers", { method: "GET" });
}

export function saveProvider(payload) {
  return request("/api/v2/providers", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function deleteProvider(providerRef) {
  return request(`/api/v2/providers/${encodeURIComponent(providerRef)}`, { method: "DELETE" });
}

export function testDefaultProvider() {
  return request("/api/v2/provider-runtime/me", { method: "GET" });
}

export function testProvider(providerRef) {
  return request(`/api/v2/provider-runtime/test/${encodeURIComponent(providerRef)}`, {
    method: "GET",
  });
}

export function testProviderFromSettings(providerRef = null) {
  return request("/api/v2/settings/provider/test", {
    method: "POST",
    body: JSON.stringify(normalizeProviderRef(providerRef)),
  });
}

// V2 destinations
export function listDestinations() {
  return request("/api/v2/destinations", { method: "GET" });
}

export function saveDestination(payload) {
  return request("/api/v2/destinations", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function deleteDestination(destinationRef) {
  return request(`/api/v2/destinations/${encodeURIComponent(destinationRef)}`, { method: "DELETE" });
}


// V2 admin SMTP settings
export function getAdminSmtpSettings() {
  return request("/api/v2/admin/smtp-settings", {
    method: "GET",
  });
}

export function saveAdminSmtpSettings(payload) {
  return request("/api/v2/admin/smtp-settings", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function testAdminSmtpSettings() {
  return request("/api/v2/admin/smtp-settings/test", {
    method: "POST",
  });
}

export function testDestination(destinationRef) {
  return request(`/api/v2/destinations/${encodeURIComponent(destinationRef)}/test`, {
    method: "POST",
  });
}

export function testDestinationFromSettings(destinationRef = null) {
  return request("/api/v2/settings/destination/test", {
    method: "POST",
    body: JSON.stringify(normalizeDestinationRef(destinationRef)),
  });
}

// V2 notification tests - placeholders backend
export function testNotificationConfig(payload) {
  return request("/api/v2/settings/notification/test", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

// V2 notification configs
export function listNotificationConfigs() {
  return request("/api/v2/notifications/configs", {
    method: "GET",
  });
}

export function createNotificationConfig(payload) {
  return request("/api/v2/notifications/configs", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getNotificationConfig(configId) {
  return request(`/api/v2/notifications/configs/${encodeURIComponent(configId)}`, {
    method: "GET",
  });
}

export function updateNotificationConfig(configId, payload) {
  return request(`/api/v2/notifications/configs/${encodeURIComponent(configId)}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function deleteNotificationConfig(configId) {
  return request(`/api/v2/notifications/configs/${encodeURIComponent(configId)}`, {
    method: "DELETE",
  });
}
export function testStoredNotificationConfig(configId) {
  return request(`/api/v2/notifications/configs/${encodeURIComponent(configId)}/test`, {
    method: "POST",
  });
}
// V2 notification rules
export function listNotificationRules() {
  return request("/api/v2/notifications/rules", {
    method: "GET",
  });
}

export function createNotificationRule(payload) {
  return request("/api/v2/notifications/rules", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getNotificationRule(ruleId) {
  return request(`/api/v2/notifications/rules/${encodeURIComponent(ruleId)}`, {
    method: "GET",
  });
}

export function updateNotificationRule(ruleId, payload) {
  return request(`/api/v2/notifications/rules/${encodeURIComponent(ruleId)}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function deleteNotificationRule(ruleId) {
  return request(`/api/v2/notifications/rules/${encodeURIComponent(ruleId)}`, {
    method: "DELETE",
  });
}
export function listNotificationEvents(limit = 50) {
  return request(`/api/v2/notifications/events?limit=${encodeURIComponent(limit)}`, {
    method: "GET",
  });
}
// V2 admin app settings
export function getAdminSecuritySettings() {
  return request("/api/v2/admin/app-settings/security", {
    method: "GET",
  });
}

export function saveAdminSecuritySettings(payload) {
  return request("/api/v2/admin/app-settings/security", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function getAdminCleanupSettings() {
  return request("/api/v2/admin/app-settings/cleanup", {
    method: "GET",
  });
}

export function saveAdminCleanupSettings(payload) {
  return request("/api/v2/admin/app-settings/cleanup", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function runAdminCleanup() {
  return request("/api/v2/admin/cleanup/run", {
    method: "POST",
  });
}

export function getAdminMaintenanceStatus() {
  return request("/api/v2/admin/maintenance/status", {
    method: "GET",
  });
}
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

export function getAdminRestartCooldowns() {
  return request("/api/v2/admin/timeouts/restart-cooldowns", {
    method: "GET",
  });
}

export function saveAdminRestartCooldowns(payload) {
  return request("/api/v2/admin/timeouts/restart-cooldowns", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}
// V2 admin runtime settings
export function getAdminRuntimeSettings() {
  return request("/api/v2/admin/app-settings/runtime", {
    method: "GET",
  });
}

export function saveAdminRuntimeSettings(payload) {
  return request("/api/v2/admin/app-settings/runtime", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function getAdminNotificationDispatcherStatus() {
  return request("/api/v2/admin/notifications/dispatcher/status", {
    method: "GET",
  });
}

export function runAdminNotificationDispatcherOnce(limit = 25) {
  return request("/api/v2/admin/notifications/dispatcher/run-once", {
    method: "POST",
    body: JSON.stringify({ limit }),
  });
}

export function getAdminGeneralSettings() {
  return request("/api/v2/admin/app-settings/general", { method: "GET" });
}

export function saveAdminGeneralSettings(payload) {
  return request("/api/v2/admin/app-settings/general", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function listActiveAnnouncements() {
  return request("/api/v2/announcements/active", { method: "GET" });
}

export function listUserAnnouncements() {
  return request("/api/v2/announcements", { method: "GET" });
}

export function openAnnouncement(id) {
  return request(`/api/v2/announcements/${id}/open`, { method: "POST" });
}

export function readAnnouncement(id) {
  return request(`/api/v2/announcements/${id}/read`, { method: "POST" });
}

export function acknowledgeAnnouncement(id) {
  return request(`/api/v2/announcements/${id}/acknowledge`, { method: "POST" });
}

export function listAdminAnnouncements() {
  return request("/api/v2/admin/announcements", { method: "GET" });
}

export function createAdminAnnouncement(payload) {
  return request("/api/v2/admin/announcements", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getAdminAnnouncement(id) {
  return request(`/api/v2/admin/announcements/${id}`, { method: "GET" });
}

export function updateAdminAnnouncement(id, payload) {
  return request(`/api/v2/admin/announcements/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function deleteAdminAnnouncement(id) {
  return request(`/api/v2/admin/announcements/${id}`, { method: "DELETE" });
}

export function getAdminAnnouncementTracking(id) {
  return request(`/api/v2/admin/announcements/${id}/tracking`, { method: "GET" });
}

export function listEmailTemplates() {
  return request("/api/v2/admin/email-templates", { method: "GET" });
}

export function getEmailTemplate(templateKey, language) {
  return request(`/api/v2/admin/email-templates/${encodeURIComponent(templateKey)}/${encodeURIComponent(language)}`, { method: "GET" });
}

export function saveEmailTemplate(templateKey, language, payload) {
  return request(`/api/v2/admin/email-templates/${encodeURIComponent(templateKey)}/${encodeURIComponent(language)}`, { method: "PUT", body: JSON.stringify(payload) });
}

export function previewEmailTemplate(templateKey, language, payload) {
  return request(`/api/v2/admin/email-templates/${encodeURIComponent(templateKey)}/${encodeURIComponent(language)}/preview`, { method: "POST", body: JSON.stringify(payload) });
}

export function resetEmailTemplate(templateKey, language) {
  return request(`/api/v2/admin/email-templates/${encodeURIComponent(templateKey)}/${encodeURIComponent(language)}/reset`, { method: "POST" });
}

// V2 admin anti-abuse
export function getAdminAntiAbuse() {
  return request("/api/v2/admin/security/anti-abuse", { method: "GET" });
}

export function resetAdminAntiAbuseAll() {
  return request("/api/v2/admin/security/anti-abuse/reset", { method: "POST" });
}

export function resetAdminAntiAbuseKind(kind) {
  return request(`/api/v2/admin/security/anti-abuse/reset/${encodeURIComponent(kind)}`, { method: "POST" });
}

// User public space
export function getMyPublicSpace() {
  return request("/api/v2/me/public-space", { method: "GET" });
}

export function cleanMyPublicSpace() {
  return request("/api/v2/me/public-space/cleanup", { method: "POST" });
}
