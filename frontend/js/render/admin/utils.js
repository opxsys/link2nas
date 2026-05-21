import { t } from "../../i18n/index.js";

export function html(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

export function toInputDateTime(value) {
  if (!value) return "";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";

  const pad = (n) => String(n).padStart(2, "0");

  return [
    date.getFullYear(),
    "-",
    pad(date.getMonth() + 1),
    "-",
    pad(date.getDate()),
    "T",
    pad(date.getHours()),
    ":",
    pad(date.getMinutes()),
  ].join("");
}

export function renderStatusBadge(label, variant = "") {
  return `<span class="badge ${variant ? `badge-${variant}` : ""}">${html(label)}</span>`;
}

export function renderComingSoonCard(title, description) {
  return `
    <article class="admin-placeholder-card">
      <div>
        <h4>${html(title)}</h4>
        <p class="muted">${html(description)}</p>
      </div>
      <span class="badge">À venir</span>
    </article>
  `;
}

export function formatBytes(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = n;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  return `${size.toFixed(unitIndex === 0 ? 0 : 2)} ${units[unitIndex]}`;
}

export function renderMaintenanceCheck(label, ok, message = "") {
  return `
    <article class="admin-placeholder-card">
      <div>
        <h4>${html(label)}</h4>
        <p class="muted">${html(message || (ok ? "OK" : t("admin.maintenance.error")))}</p>
      </div>
      <span class="badge ${ok ? "badge-ready" : "badge-failed"}">
        ${ok ? "OK" : "KO"}
      </span>
    </article>
  `;
}

export function renderJsonBlock(value) {
  return html(JSON.stringify(value || {}, null, 2));
}
