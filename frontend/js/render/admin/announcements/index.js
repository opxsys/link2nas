import { formatDate } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { html, toInputDateTime } from "../utils.js";

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

export function renderAnnouncementForm(ann = null, emailAvailable = false) {
  const isEdit = Boolean(ann?.id);
  const v = (field, fallback = "") => html(ann ? (ann[field] ?? fallback) : fallback);
  const checked = (field) => (ann ? Boolean(ann[field]) : false);

  return `
    <form id="${isEdit ? `announcement-edit-form-${ann.id}` : "announcement-create-form"}" class="form-grid announcement-form" ${isEdit ? `data-announcement-id="${html(ann.id)}"` : ""}>
      <label>
        <span>${t("admin.announcements.field_title")}</span>
        <input name="title" type="text" value="${v("title")}" required />
      </label>

      <label>
        <span>${t("admin.announcements.field_body")}</span>
        <textarea name="body" rows="4" required>${v("body")}</textarea>
      </label>

      <div class="admin-form-grid-2">
        <label>
          <span>${t("admin.announcements.field_type")}</span>
          <select name="type">
            <option value="news" ${(!ann || ann.type === "news") ? "selected" : ""}>${t("admin.announcements.type_news")}</option>
            <option value="maintenance" ${ann?.type === "maintenance" ? "selected" : ""}>${t("admin.announcements.type_maintenance")}</option>
            <option value="incident" ${ann?.type === "incident" ? "selected" : ""}>${t("admin.announcements.type_incident")}</option>
            <option value="security" ${ann?.type === "security" ? "selected" : ""}>${t("admin.announcements.type_security")}</option>
          </select>
        </label>

        <label>
          <span>${t("admin.announcements.field_severity")}</span>
          <select name="severity">
            <option value="info" ${(!ann || ann.severity === "info") ? "selected" : ""}>${t("admin.announcements.severity_info")}</option>
            <option value="warning" ${ann?.severity === "warning" ? "selected" : ""}>${t("admin.announcements.severity_warning")}</option>
            <option value="critical" ${ann?.severity === "critical" ? "selected" : ""}>${t("admin.announcements.severity_critical")}</option>
          </select>
        </label>
      </div>

      <div class="admin-form-grid-2">
        <label>
          <span>${t("admin.announcements.field_starts_at")}</span>
          <input name="starts_at" type="datetime-local" value="${html(toInputDateTime(ann?.starts_at))}" />
        </label>

        <label>
          <span>${t("admin.announcements.field_ends_at")}</span>
          <input name="ends_at" type="datetime-local" value="${html(toInputDateTime(ann?.ends_at))}" />
        </label>
      </div>

      <div class="admin-checkbox-grid">
        <label class="checkbox-row">
          <input type="checkbox" name="is_active" ${isEdit ? (checked("is_active") ? "checked" : "") : "checked"} />
          <span>${t("admin.announcements.field_is_active")}</span>
        </label>

        <label class="checkbox-row">
          <input type="checkbox" name="show_as_banner" ${checked("show_as_banner") ? "checked" : ""} />
          <span>${t("admin.announcements.field_show_as_banner")}</span>
        </label>

        <label class="checkbox-row">
          <input type="checkbox" name="require_acknowledgement" ${checked("require_acknowledgement") ? "checked" : ""} />
          <span>${t("admin.announcements.field_require_acknowledgement")}</span>
        </label>
        <p class="announcement-form-hint">${t("admin.announcements.field_require_acknowledgement_hint")}</p>

        <label class="checkbox-row">
          <input type="checkbox" name="track_open" ${checked("track_open") ? "checked" : ""} />
          <span>${t("admin.announcements.field_track_open")}</span>
        </label>

        <label class="checkbox-row ${emailAvailable ? "" : "is-disabled"}">
          <input type="checkbox" name="send_email" ${emailAvailable ? (isEdit && ann?.send_email ? "checked" : "") : "disabled"} />
          <span>${t("admin.announcements.field_send_email")}</span>
        </label>
      </div>

      <p class="announcement-form-hint">${emailAvailable
        ? t("admin.announcements.email_eligible_hint")
        : t("admin.announcements.email_smtp_required")
      }</p>

      <div class="admin-form-actions">
        <button type="submit" class="btn btn-primary">
          ${isEdit ? t("admin.announcements.update_submit") : t("admin.announcements.create_submit")}
        </button>
        ${isEdit ? `<button type="button" class="btn" data-action="cancel-announcement-edit" data-id="${html(ann.id)}">${t("admin.announcements.cancel_edit")}</button>` : ""}
      </div>
    </form>
  `;
}

function renderAnnouncementCard(ann) {
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

export function renderAnnouncementsAdminPanel(announcements = [], emailAvailable = false) {
  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="announcements" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.announcements.title")}</h3>
          <p class="muted">${t("admin.announcements.subtitle")}</p>
        </div>
        <span class="badge">${announcements.length} ${announcements.length > 1 ? t("admin.announcements.count_plural") : t("admin.announcements.count_singular")}</span>
      </div>

      <div id="admin-announcements-feedback" hidden></div>

      <details class="admin-section-card admin-create-user-block">
        <summary>
          <span>
            <strong>${t("admin.announcements.create_title")}</strong>
          </span>
        </summary>
        ${renderAnnouncementForm(null, emailAvailable)}
      </details>

      <div class="announcement-admin-list">
        ${announcements.length
          ? announcements.map(renderAnnouncementCard).join("")
          : `<p class="muted">${t("admin.announcements.no_items")}</p>`
        }
      </div>
    </section>
  `;
}
