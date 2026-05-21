import { formatDate } from "../../utils.js";
import { t } from "../../i18n/index.js";
import {
  html,
  toInputDateTime,
  renderStatusBadge,
  renderComingSoonCard,
  formatBytes,
  renderMaintenanceCheck,
  renderJsonBlock,
} from "./utils.js";
import { renderUserCard, renderCreateUserBlock, renderUserCardList } from "./users.js";
import { renderGeneralSettingsPanel } from "./general.js";
import { renderSmtpSettingsPanel } from "./smtp.js";
import { renderSecuritySettingsPanel } from "./security.js";
import { renderAntiAbuseSection } from "./anti-abuse.js";
import { renderCleanupSettingsPanel } from "./cleanup.js";
import { renderTimeoutsSettingsPanel } from "./timeouts.js";
import { renderMaintenanceStatusPanel } from "./maintenance.js";
import { renderRuntimeSettingsPanel } from "./runtime.js";
import { renderEmailTemplatesPanel } from "./email-templates.js";

export { renderUserCardList, renderAntiAbuseSection };


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

function renderAdminSectionPlaceholders(
  smtpSettings = null,
  securitySettings = null,
  cleanupSettings = null,
  maintenanceStatus = null,
  timeoutSettings = null,
  runtimeSettings = null,
  generalSettings = null,
  announcements = [],
  emailAvailable = false
) {
  return `
    ${renderGeneralSettingsPanel(generalSettings)}
    ${renderAnnouncementsAdminPanel(announcements, emailAvailable)}
    ${renderSmtpSettingsPanel(smtpSettings)}
    ${renderEmailTemplatesPanel()}
    ${renderSecuritySettingsPanel(securitySettings)}
    ${renderCleanupSettingsPanel(cleanupSettings)}

    ${renderTimeoutsSettingsPanel(timeoutSettings)}
    ${renderRuntimeSettingsPanel(runtimeSettings)}

    ${renderMaintenanceStatusPanel(maintenanceStatus)}
  `;
}


export function renderUsersPanel(
  users = [],
  smtpSettings = null,
  securitySettings = null,
  cleanupSettings = null,
  maintenanceStatus = null,
  timeoutSettings = null,
  runtimeSettings = null,
  options = {},
  generalSettings = null,
  announcements = []
) {
  const container = document.getElementById("users-panel");
  if (!container) return;

  const singleUserMode = Boolean(options.singleUserMode);
  const emailAvailable = Boolean(options.emailAvailable !== false);

  const usersTab = singleUserMode
    ? ""
    : `<button type="button" class="admin-tab is-active" data-admin-tab="users">${t("admin.tab.users")}</button>`;

  const usersPanel = singleUserMode
    ? ""
    : `
      <section class="admin-section-card admin-tab-panel" data-admin-panel="users">
        <div class="admin-section-title">
          <div>
            <h3>${t("admin.users.title")}</h3>
            <p class="muted">${t("admin.users.subtitle")}</p>
          </div>
          <span class="badge">${users.length} ${users.length > 1 ? t("admin.users.count_plural") : t("admin.users.count_singular")}</span>
        </div>

        <div id="admin-users-feedback" hidden></div>

        <div class="admin-users-toolbar">
          <input
            id="admin-users-search"
            type="search"
            placeholder="${t("admin.users.search_placeholder")}"
          />
          <div class="admin-users-filters">
            <button type="button" class="filter-chip is-active" data-admin-users-filter="all">${t("admin.users.filter_all")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="active">${t("admin.users.filter_active")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="disabled">${t("admin.users.filter_disabled")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="super-admin">${t("admin.users.filter_super_admin")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="email-unverified">${t("admin.users.filter_email_unverified")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="expired">${t("admin.users.filter_expired")}</button>
          </div>
        </div>

        ${renderCreateUserBlock()}

        <div class="admin-users-list">
          ${users.length ? users.map((u) => renderUserCard(u, emailAvailable)).join("") : `<div class="empty-state">${t("admin.users.empty")}</div>`}
        </div>
      </section>
    `;

  container.innerHTML = `
    <div class="admin-page">
      <div class="section-header admin-page-header">
        <div>
          <h2>${t("admin.page.title")}</h2>
          <p class="muted">
            ${singleUserMode ? t("admin.page.subtitle_single_user") : t("admin.page.subtitle")}
          </p>
        </div>

        ${
          singleUserMode
            ? `<span class="badge badge-warning">${t("settings.account.single_user_title")}</span>`
            : ""
        }
      </div>

      <div class="admin-tabs">
        ${usersTab}
        <button type="button" class="admin-tab" data-admin-tab="general">${t("admin.tab.general")}</button>
        <button type="button" class="admin-tab" data-admin-tab="announcements">${t("admin.tab.announcements")}</button>
        <button type="button" class="admin-tab ${singleUserMode ? "is-active" : ""}" data-admin-tab="maintenance">${t("admin.tab.maintenance")}</button>
        <button type="button" class="admin-tab" data-admin-tab="smtp">${t("admin.tab.smtp")}</button>
        <button type="button" class="admin-tab" data-admin-tab="email-templates">${t("admin.tab.email_templates")}</button>
        <button type="button" class="admin-tab" data-admin-tab="security">${t("admin.tab.security")}</button>
        <button type="button" class="admin-tab" data-admin-tab="timeouts">${t("admin.tab.timeouts")}</button>
        <button type="button" class="admin-tab" data-admin-tab="runtime">${t("admin.tab.runtime")}</button>
        <button type="button" class="admin-tab" data-admin-tab="cleanup">${t("admin.tab.cleanup")}</button>
      </div>

      ${
        singleUserMode
          ? `
            <section class="admin-section-card">
              <div class="admin-section-title">
                <div>
                  <h3>${t("admin.users.single_user_warning_title")}</h3>
                  <p class="muted">${t("admin.users.single_user_warning_text")}</p>
                </div>
              </div>
            </section>
          `
          : ""
      }

      ${usersPanel}
      ${renderAdminSectionPlaceholders(
        smtpSettings,
        securitySettings,
        cleanupSettings,
        maintenanceStatus,
        timeoutSettings,
        runtimeSettings,
        generalSettings,
        announcements,
        emailAvailable
      )}
    </div>
  `;
}
