import { ApiError, request } from "./request.js";

export { ApiError };
export * from "./auth.js";
export * from "./system.js";
export * from "./jobs.js";
export * from "./providers.js";
export * from "./destinations.js";
export * from "./notifications.js";
export * from "./admin-users.js";

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
