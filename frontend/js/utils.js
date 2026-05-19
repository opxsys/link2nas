import { t } from "./i18n/index.js";


export function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function formatBytes(value) {
  if (value == null || Number.isNaN(Number(value))) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value);
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(unitIndex === 0 ? 0 : 2)} ${units[unitIndex]}`;
}

export function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function statusBadgeClass(status) {
  return `badge badge-${String(status || "unknown").toLowerCase()}`;
}

export function showAppMessage(message, type = "info") {
  const container = document.getElementById("app-message");
  if (!container) return;

  container.className = `app-message is-${type}`;
  container.textContent = message;

  window.clearTimeout(showAppMessage._timer);
  showAppMessage._timer = window.setTimeout(() => {
    container.textContent = "";
    container.className = "";
  }, 3000);
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    console.error("Clipboard error:", e);
    return false;
  }
}



export function formatJobStatus(status) {
  return t(`status.${status}`) || status;
}