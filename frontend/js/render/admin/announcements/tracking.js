import { formatDate } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { html } from "../utils.js";

export function renderAnnouncementTrackingPanel(tracking) {
  if (!tracking) return "";

  const ann = tracking.announcement || {};
  const stats = tracking.stats || {};
  const reads = Array.isArray(tracking.reads) ? tracking.reads : [];

  const showEmailTracking =
    Boolean(ann.send_email) ||
    (stats.targeted_email_recipients ?? 0) > 0 ||
    (stats.email_sent ?? 0) > 0 ||
    (stats.email_failed ?? 0) > 0 ||
    reads.some((r) => r.email_sent_at || r.email_status || r.email_error);

  return `
    <div class="announcement-tracking-panel">
      <div class="admin-section-title" style="margin-bottom:12px">
        <div>
          <h4>${t("admin.announcements.tracking_title")}: ${html(ann.title || "")}</h4>
        </div>
      </div>

      <div class="announcement-tracking-stats">
        <div class="announcement-tracking-stat-card">
          <span class="announcement-tracking-stat-value">${stats.opened ?? 0}</span>
          <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_opened")}</span>
        </div>
        <div class="announcement-tracking-stat-card">
          <span class="announcement-tracking-stat-value">${stats.read ?? 0}</span>
          <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_read")}</span>
        </div>
        <div class="announcement-tracking-stat-card">
          <span class="announcement-tracking-stat-value">${stats.acknowledged ?? 0}</span>
          <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_acked")}</span>
        </div>
        ${showEmailTracking ? `
          <div class="announcement-tracking-stat-card">
            <span class="announcement-tracking-stat-value">${stats.email_sent ?? 0}</span>
            <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_email_sent")}</span>
          </div>
          <div class="announcement-tracking-stat-card">
            <span class="announcement-tracking-stat-value">${stats.email_failed ?? 0}</span>
            <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_email_failed")}</span>
          </div>
          <div class="announcement-tracking-stat-card">
            <span class="announcement-tracking-stat-value">${stats.targeted_email_recipients ?? 0}</span>
            <span class="announcement-tracking-stat-label">${t("admin.announcements.tracking_targeted")}</span>
          </div>
        ` : ""}
      </div>

      ${reads.length === 0 ? `<p class="muted">${t("admin.announcements.no_tracking")}</p>` : `
        <table class="announcement-tracking-table">
          <thead>
            <tr>
              <th>${t("admin.announcements.tracking_col_email")}</th>
              <th>${t("admin.announcements.tracking_col_name")}</th>
              <th>${t("admin.announcements.tracking_col_opened")}</th>
              <th>${t("admin.announcements.tracking_col_read")}</th>
              <th>${t("admin.announcements.tracking_col_acked")}</th>
              ${showEmailTracking ? `
                <th>${t("admin.announcements.tracking_col_email_sent")}</th>
                <th>${t("admin.announcements.tracking_col_email_status")}</th>
              ` : ""}
            </tr>
          </thead>
          <tbody>
            ${reads.map((r) => `
              <tr>
                <td>${html(r.email || "—")}</td>
                <td>${html(r.display_name || "—")}</td>
                <td>${r.opened_at ? html(formatDate(r.opened_at)) : "—"}</td>
                <td>${r.read_at ? html(formatDate(r.read_at)) : "—"}</td>
                <td>${r.acknowledged_at ? html(formatDate(r.acknowledged_at)) : "—"}</td>
                ${showEmailTracking ? `
                  <td>${r.email_sent_at ? html(formatDate(r.email_sent_at)) : "—"}</td>
                  <td>${html(r.email_status || "—")}</td>
                ` : ""}
              </tr>
            `).join("")}
          </tbody>
        </table>
      `}
    </div>
  `;
}
