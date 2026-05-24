import { formatDate } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { html } from "../utils.js";

function formatAnnouncementType(type) {
  const map = {
    news: "admin.announcements.type_news",
    maintenance: "admin.announcements.type_maintenance",
    incident: "admin.announcements.type_incident",
    security: "admin.announcements.type_security",
  };
  return t(map[type] || "admin.announcements.type_news");
}

function formatAnnouncementSeverity(severity) {
  const map = {
    info: "admin.announcements.severity_info",
    warning: "admin.announcements.severity_warning",
    critical: "admin.announcements.severity_critical",
  };
  return t(map[severity] || "admin.announcements.severity_info");
}

export function renderAnnouncementCard(ann) {
  const stats = ann.stats || {};
  const isActive = Boolean(ann.is_active);

  return `
    <article class="announcement-card" data-announcement-id="${html(ann.id)}">
      <div class="announcement-card-header">
        <div class="announcement-badges">
          <span class="announcement-severity-badge severity-${html(ann.severity || "info")}">${html(formatAnnouncementSeverity(ann.severity))}</span>
          <span class="announcement-type-badge">${html(formatAnnouncementType(ann.type))}</span>
          <span class="badge ${isActive ? "badge-ready" : ""}">${t(isActive ? "admin.announcements.badge_active" : "admin.announcements.badge_inactive")}</span>
          ${ann.show_as_banner ? `<span class="badge">${t("admin.announcements.field_show_as_banner")}</span>` : ""}
          ${ann.require_acknowledgement ? `<span class="badge">${t("admin.announcements.field_require_acknowledgement")}</span>` : ""}
        </div>
      </div>

      <div class="announcement-card-title">${html(ann.title)}</div>
      <div class="announcement-card-body-preview">${html(ann.body)}</div>

      <div class="announcement-card-meta">
        ${ann.starts_at ? `<span>${t("admin.announcements.field_starts_at")}: <strong>${html(formatDate(ann.starts_at))}</strong></span>` : ""}
        ${ann.ends_at ? `<span>${t("admin.announcements.field_ends_at")}: <strong>${html(formatDate(ann.ends_at))}</strong></span>` : ""}
        <span>${t("admin.announcements.created_at")}: <strong>${ann.created_at ? html(formatDate(ann.created_at)) : "—"}</strong></span>
      </div>

      ${Object.keys(stats).length ? `
        <div class="announcement-card-stats">
          <span class="announcement-stat"><strong>${stats.opened ?? 0}</strong> ${t("admin.announcements.tracking_opened")}</span>
          <span class="announcement-stat"><strong>${stats.read ?? 0}</strong> ${t("admin.announcements.tracking_read")}</span>
          <span class="announcement-stat"><strong>${stats.acknowledged ?? 0}</strong> ${t("admin.announcements.tracking_acked")}</span>
          ${stats.targeted_email_recipients != null ? `<span class="announcement-stat"><strong>${stats.targeted_email_recipients}</strong> ${t("admin.announcements.tracking_targeted")}</span>` : ""}
        </div>
      ` : ""}

      <div class="announcement-card-actions">
        <button type="button" class="btn" data-action="edit-announcement" data-id="${html(ann.id)}">
          ${t("admin.announcements.edit")}
        </button>
        <button type="button" class="btn" data-action="${isActive ? "deactivate-announcement" : "activate-announcement"}" data-id="${html(ann.id)}">
          ${isActive ? t("admin.announcements.toggle_deactivate") : t("admin.announcements.toggle_activate")}
        </button>
        <button type="button" class="btn" data-action="view-announcement-tracking" data-id="${html(ann.id)}">
          ${t("admin.announcements.tracking")}
        </button>
        <button type="button" class="btn btn-danger" data-action="delete-announcement" data-id="${html(ann.id)}">
          ${t("admin.announcements.delete")}
        </button>
      </div>

      <div class="announcement-edit-inline" data-for-announcement="${html(ann.id)}" hidden></div>
      <div class="announcement-tracking-inline" data-for-tracking="${html(ann.id)}" hidden></div>
    </article>
  `;
}
