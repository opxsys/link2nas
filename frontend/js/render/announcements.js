import { t } from "../i18n/index.js";
import { formatDate } from "../utils.js";

function html(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatSeverityLabel(severity) {
  if (severity === "critical") return t("admin.announcements.severity_critical");
  if (severity === "warning") return t("admin.announcements.severity_warning");
  return t("admin.announcements.severity_info");
}

function formatTypeLabel(type) {
  const map = {
    news: "admin.announcements.type_news",
    maintenance: "admin.announcements.type_maintenance",
    incident: "admin.announcements.type_incident",
    security: "admin.announcements.type_security",
  };
  return t(map[type] || "admin.announcements.type_news");
}

function renderAnnouncementUserCard(ann) {
  const status = ann.user_status || {};
  const isAcked = Boolean(status.acknowledged_at);
  const isRead = Boolean(status.read_at);
  const requiresAck = Boolean(ann.require_acknowledgement);
  const needsAck = requiresAck && !isAcked;
  const needsRead = !requiresAck && !isRead;

  return `
    <article class="announcement-user-card" data-ann-id="${html(ann.id)}">
      <div class="announcement-user-card-header">
        <span class="announcement-severity-badge severity-${html(ann.severity || "info")}">${html(formatSeverityLabel(ann.severity))}</span>
        <span class="announcement-type-badge">${html(formatTypeLabel(ann.type))}</span>
        ${isAcked
          ? `<span class="badge badge-ready">${t("announcements.acknowledged")}</span>`
          : isRead
            ? `<span class="badge badge-ready">${t("announcements.read")}</span>`
            : ""}
        <span class="announcement-user-card-title">${html(ann.title)}</span>
      </div>

      <div class="announcement-user-card-body">${html(ann.body)}</div>

      ${(ann.starts_at || ann.ends_at) ? `
        <div class="announcement-user-card-dates">
          ${ann.starts_at ? `${html(t("admin.announcements.field_starts_at"))}: ${html(formatDate(ann.starts_at))}` : ""}
          ${ann.starts_at && ann.ends_at ? " &mdash; " : ""}
          ${ann.ends_at ? `${html(t("admin.announcements.field_ends_at"))}: ${html(formatDate(ann.ends_at))}` : ""}
        </div>
      ` : ""}

      <div class="announcement-user-card-actions">
        ${needsAck ? `
          <span class="announcement-ack-hint">${t("announcements.ack_hint")}</span>
          <button class="btn btn-primary" data-ann-action="acknowledge" data-ann-id="${html(ann.id)}">${t("announcements.acknowledge")}</button>
        ` : needsRead ? `
          <button class="btn" data-ann-action="read" data-ann-id="${html(ann.id)}">${t("announcements.mark_read")}</button>
        ` : ""}
      </div>
    </article>
  `;
}

export function renderAnnouncementsPage(announcements = [], isSuperAdmin = false) {
  const container = document.getElementById("announcements-panel");
  if (!container) return;

  container.innerHTML = `
    <div class="section-header">
      <div>
        <h2>${t("announcements.title")}</h2>
      </div>
      ${isSuperAdmin ? `
        <button class="btn" data-ann-action="goto-create-announcement">${t("announcements.create_shortcut")}</button>
      ` : ""}
    </div>

    <div class="announcements-list">
      ${announcements.length
        ? announcements.map(renderAnnouncementUserCard).join("")
        : `<p class="muted">${t("announcements.no_items")}</p>`
      }
    </div>
  `;
}
