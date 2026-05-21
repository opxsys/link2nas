import { request } from "./request.js";

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
