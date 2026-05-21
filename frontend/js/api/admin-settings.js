import { request } from "./request.js";

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
