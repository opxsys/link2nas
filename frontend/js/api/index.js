import { ApiError, request } from "./request.js";

export { ApiError };
export * from "./auth.js";
export * from "./system.js";
export * from "./jobs.js";
export * from "./providers.js";
export * from "./destinations.js";
export * from "./notifications.js";
export * from "./admin-users.js";
export * from "./admin-settings.js";

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

// User public space
export function getMyPublicSpace() {
  return request("/api/v2/me/public-space", { method: "GET" });
}

export function cleanMyPublicSpace() {
  return request("/api/v2/me/public-space/cleanup", { method: "POST" });
}
