import { t } from "../../i18n/index.js";
import { state } from "../../state.js";

export const VALID_SETTINGS_TABS = ["account", "providers", "destinations", "api_keys", "notifications", "prowlarr", "espace"];

export function getActiveSettingsTab() {
  try {
    const stored = localStorage.getItem("settings_tab");
    return VALID_SETTINGS_TABS.includes(stored) ? stored : "account";
  } catch {
    return "account";
  }
}

export function setActiveSettingsTab(tab) {
  try {
    localStorage.setItem("settings_tab", tab);
  } catch {
    // localStorage unavailable — state is ephemeral only
  }
}

export function getActiveNotificationSubtab() {
  try {
    const stored = localStorage.getItem("notification_subtab");
    return stored === "rules" ? "rules" : "channels";
  } catch {
    return "channels";
  }
}

export function setActiveNotificationSubtab(subtab) {
  try {
    localStorage.setItem("notification_subtab", subtab !== "rules" ? "channels" : "rules");
  } catch {}
}

export function html(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export function yesNo(value) {
  return value ? t("common.yes") : t("common.no");
}

export function formatProviderType(providerType) {
  const value = String(providerType || "").trim().toLowerCase();
  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";
  return providerType || "—";
}

export function formatDestinationType(destinationType) {
  const value = String(destinationType || "").trim().toLowerCase();
  if (value === "synology" || value === "nas") return "NAS Synology";
  if (value === "local") return "Local";
  return destinationType || "—";
}

export function formatProfileName(item, fallbackType) {
  return String(item?.name || "").trim() || fallbackType || "Sans nom";
}

export function formatExpiration(value) {
  if (!value) return "inconnue";

  const raw = String(value).trim();
  let date = null;

  if (/^\d+$/.test(raw)) {
    const timestamp = Number(raw);
    date = new Date(timestamp > 9999999999 ? timestamp : timestamp * 1000);
  } else {
    date = new Date(raw);
  }

  if (Number.isNaN(date.getTime())) {
    return raw;
  }

  return new Intl.DateTimeFormat(state.language || "fr", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let value = bytes;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

export function formatApiKeyScopes(scopes = []) {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return "aucun scope";
  }

  return scopes.join(", ");
}

export function formatNotificationChannel(channel) {
  const value = String(channel || "").trim().toLowerCase();

  if (value === "email") return "Email";
  if (value === "gotify") return "Gotify";
  if (value === "webhook") return "Webhook";

  return value || "—";
}

export function formatNotificationSeverity(severity) {
  const value = String(severity || "").trim().toLowerCase();

  if (value === "info") return "Info";
  if (value === "warning") return "Warning";
  if (value === "error") return "Error";
  if (value === "critical") return "Critical";

  return value || "—";
}

export function formatNotificationEventTypes(eventTypes = []) {
  if (!Array.isArray(eventTypes) || eventTypes.length === 0) {
    return t("settings.notifications.meta_all_events");
  }

  return eventTypes.join(", ");
}

export function formatEventTypeLabel(type) {
  const map = {
    "job.completed":      "settings.notifications.event_job_completed",
    "job.failed":         "settings.notifications.event_job_failed",
    "job.links_ready":    "settings.notifications.event_job_links_ready",
    "job.cancelled":      "settings.notifications.event_job_cancelled",
    "destination.sent":   "settings.notifications.event_destination_sent",
    "destination.failed": "settings.notifications.event_destination_failed",
    "provider.failed":    "settings.notifications.event_provider_failed",
  };
  const key = map[String(type || "").trim().toLowerCase()];
  return key ? t(key) : String(type);
}
