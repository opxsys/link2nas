import { request } from "./request.js";

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
