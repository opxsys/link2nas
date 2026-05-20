import { API_BASE } from "./config.js";
import { getToken } from "./core/session.js";

export class ApiError extends Error {
  constructor(message, status = 0, data = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.data = data;
  }
}

async function request(path, options = {}) {
  const isFormData = options.body instanceof FormData;
  const token = getToken();

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(isFormData ? {} : { "Content-Type": "application/json" }),
      ...(token ? { "X-Api-Key": token } : {}),
      ...(options.headers || {}),
    },
  });

  if (response.status === 204) return null;

  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();

  let data = null;
  if (text) {
    if (contentType.includes("application/json")) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { message: text };
      }
    } else {
      data = { message: text };
    }
  }

  if (!response.ok) {
    let message = data?.error || data?.message || `HTTP ${response.status}`;

    if (typeof message === "string" && message.trim().startsWith("<")) {
      message = `Erreur serveur HTTP ${response.status}`;
    }

    throw new ApiError(message, response.status, data);
  }

  return data;
}

function normalizeProviderRef(providerRef = null) {
  const value = String(providerRef || "").trim();
  if (!value) return {};
  if (["realdebrid", "alldebrid"].includes(value)) {
    return { provider_name: value };
  }
  return { provider_config_id: value };
}

function normalizeDestinationRef(destinationRef = null) {
  const value = String(destinationRef || "").trim();
  if (!value || value === "links_only") return {};
  if (["synology", "nas", "local"].includes(value)) {
    return { destination_name: value };
  }
  return { destination_config_id: value };
}

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

export function getProviderInfo() {
  return request("/api/v2/system/provider", { method: "GET" });
}

export function getControlCenterInfo() {
  return request("/api/v2/system/control-center", { method: "GET" });
}

// V2 jobs
export function getJobs(status = "") {
  const query = status ? `?status=${encodeURIComponent(status)}` : "";
  return request(`/api/v2/jobs${query}`, { method: "GET" });
}

export function getJob(jobId) {
  return request(`/api/v2/jobs/${jobId}`, { method: "GET" });
}

export function createJob(payload) {
  return request("/api/v2/jobs", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function createJobsBulk(
  sourceValue,
  autoStart = false,
  sendToDestination = false,
  providerRef = null,
  destinationRef = null
) {
  return request("/api/v2/jobs/bulk", {
    method: "POST",
    body: JSON.stringify({
      source_value: sourceValue,
      auto_start: autoStart,
      send_to_destination: sendToDestination,
      ...normalizeProviderRef(providerRef),
      ...normalizeDestinationRef(destinationRef),
    }),
  });
}

export function createTorrentFileJob(
  file,
  autoStart = false,
  sendToDestination = false,
  providerRef = null,
  destinationRef = null
) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("auto_start", autoStart ? "true" : "false");
  formData.append("send_to_destination", sendToDestination ? "true" : "false");

  const providerPayload = normalizeProviderRef(providerRef);
  if (providerPayload.provider_config_id) {
    formData.append("provider_config_id", providerPayload.provider_config_id);
  } else if (providerPayload.provider_name) {
    formData.append("provider_name", providerPayload.provider_name);
  }

  const destinationPayload = normalizeDestinationRef(destinationRef);
  if (destinationPayload.destination_config_id) {
    formData.append("destination_config_id", destinationPayload.destination_config_id);
  } else if (destinationPayload.destination_name) {
    formData.append("destination_name", destinationPayload.destination_name);
  }

  return request("/api/v2/jobs/torrent-file", {
    method: "POST",
    body: formData,
  });
}

export function startJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/start`, { method: "POST" });
}

export function refreshJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/refresh`, { method: "POST" });
}

export function cancelJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/cancel`, { method: "POST" });
}

export function restartJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/restart`, { method: "POST" });
}

export function deleteJob(jobId) {
  return request(`/api/v2/jobs/${jobId}`, { method: "DELETE" });
}

export function selectJobFiles(jobId, files = "all") {
  return request(`/api/v2/jobs/${jobId}/select-files`, {
    method: "POST",
    body: JSON.stringify({ files }),
  });
}

export function unrestrictJob(jobId) {
  return request(`/api/v2/jobs/${jobId}/unrestrict`, { method: "POST" });
}

export function unrestrictJobFile(jobId, fileId) {
  return request(`/api/v2/jobs/${jobId}/files/${fileId}/unrestrict`, {
    method: "POST",
  });
}

export function sendJobToDestination(jobId, destinationRef = null) {
  return request(`/api/v2/jobs/${jobId}/send-to-destination`, {
    method: "POST",
    body: JSON.stringify({
      ...normalizeDestinationRef(destinationRef),
    }),
  });
}

export function resendJobToDestination(jobId, destinationRef = null) {
  return request(`/api/v2/jobs/${jobId}/resend`, {
    method: "POST",
    body: JSON.stringify({
      ...normalizeDestinationRef(destinationRef),
    }),
  });
}

export function cancelLocalDestinationDownload(jobId) {
  return request(`/api/v2/jobs/${jobId}/destination/cancel`, {
    method: "POST",
  });
}

export function cloneJobWithProvider(
  jobId,
  providerRef,
  destinationRef = null,
  autoStart = true
) {
  return request(`/api/v2/jobs/${jobId}/clone-with-provider`, {
    method: "POST",
    body: JSON.stringify({
      ...normalizeProviderRef(providerRef),
      ...normalizeDestinationRef(destinationRef),
      auto_start: autoStart,
    }),
  });
}

// Compat frontend existant
export function resyncProvider(jobId) {
  return refreshJob(jobId);
}



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