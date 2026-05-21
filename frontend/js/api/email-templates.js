import { request } from "./request.js";

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
