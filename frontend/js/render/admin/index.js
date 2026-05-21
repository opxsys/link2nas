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

export { renderUserCardList, renderAntiAbuseSection };


function renderEmailTemplatesPanel() {
  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="email-templates" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.email_templates.title")}</h3>
          <p class="muted">${t("admin.email_templates.description")}</p>
        </div>
      </div>

      <div id="admin-email-templates-feedback" hidden></div>

      <div class="email-template-selector">
        <label>
          <span>${t("admin.email_templates.template")}</span>
          <select id="email-template-key-select"></select>
        </label>
        <label>
          <span>${t("admin.email_templates.language")}</span>
          <select id="email-template-lang-select">
            <option value="fr">${t("settings.account.language_fr")}</option>
            <option value="en">${t("settings.account.language_en")}</option>
          </select>
        </label>
        <span id="email-template-custom-badge" class="badge"></span>
      </div>

      <div id="email-template-variables-block" class="detail-block" hidden>
        <h4>${t("admin.email_templates.variables")}</h4>
        <div id="email-template-variables" class="email-template-variables"></div>
      </div>

      <div class="form-grid">
        <label>
          <span>${t("admin.email_templates.subject")}</span>
          <input type="text" id="email-template-subject" />
        </label>
        <label>
          <span>${t("admin.email_templates.body")}</span>
          <textarea id="email-template-body" rows="14"></textarea>
        </label>
      </div>

      <div class="admin-form-actions">
        <button type="button" class="btn btn-primary" id="email-template-save-btn" data-action="email-template-save">
          ${t("admin.email_templates.save")}
        </button>
        <button type="button" class="btn" id="email-template-preview-btn" data-action="email-template-preview">
          ${t("admin.email_templates.preview")}
        </button>
        <button type="button" class="btn btn-danger" id="email-template-reset-btn" data-action="email-template-reset">
          ${t("admin.email_templates.reset")}
        </button>
      </div>

      <div id="email-template-preview-block" hidden>
        <div class="detail-block">
          <h4>${t("admin.email_templates.preview_title")}</h4>
          <div class="email-template-preview-row">
            <strong>${t("admin.email_templates.rendered_subject")}</strong>
            <p id="email-template-preview-subject" class="email-template-preview-subject"></p>
          </div>
          <div class="email-template-preview-row">
            <strong>${t("admin.email_templates.rendered_body")}</strong>
            <pre id="email-template-preview-body" class="email-template-preview-body"></pre>
          </div>
          <details>
            <summary class="muted">${t("admin.email_templates.sample_values")}</summary>
            <pre id="email-template-preview-sample" class="email-template-preview-sample"></pre>
          </details>
        </div>
      </div>
    </section>
  `;
}

function renderCleanupSettingsPanel(cleanupSettings = null) {
  const retention = cleanupSettings?.retention || {};

  const torrentTmpDays = retention.torrent_tmp_days ?? 7;
  const completedJobsDays = retention.completed_jobs_days ?? 30;
  const failedJobsDays = retention.failed_jobs_days ?? 30;
  const cancelledJobsDays = retention.cancelled_jobs_days ?? 15;
  const expiredTokensDays = retention.expired_tokens_days ?? 7;

  // TODO V3/backlog: Advanced cleanup sections intentionally hidden for now.
  // Future sections: Manual cleanup details/results, User data cleanup.

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="cleanup" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.cleanup.title")}</h3>
          <p class="muted">${t("admin.cleanup.subtitle")}</p>
        </div>
        <span class="badge badge-ready">${t("admin.cleanup.configured")}</span>
      </div>

      <div id="admin-cleanup-feedback" hidden></div>

      <form id="admin-cleanup-form" class="form-grid">
        <div class="security-setting-grid">
          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.torrent_tmp_days")}</span>
            <div class="security-input-row">
              <input name="torrent_tmp_days" type="number" min="1" max="365" value="${html(torrentTmpDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>

          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.completed_jobs_days")}</span>
            <div class="security-input-row">
              <input name="completed_jobs_days" type="number" min="1" max="3650" value="${html(completedJobsDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>

          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.failed_jobs_days")}</span>
            <div class="security-input-row">
              <input name="failed_jobs_days" type="number" min="1" max="3650" value="${html(failedJobsDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>

          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.cancelled_jobs_days")}</span>
            <div class="security-input-row">
              <input name="cancelled_jobs_days" type="number" min="1" max="3650" value="${html(cancelledJobsDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>

          <label class="security-setting-card">
            <span class="security-setting-label">${t("admin.cleanup.expired_tokens_days")}</span>
            <div class="security-input-row">
              <input name="expired_tokens_days" type="number" min="1" max="365" value="${html(expiredTokensDays)}" required />
              <span class="security-input-unit">${t("admin.cleanup.unit_days")}</span>
            </div>
          </label>
        </div>

        <div class="admin-form-actions">
          <button type="submit" class="btn btn-primary">${t("admin.cleanup.save")}</button>
          <button type="button" class="btn btn-danger" data-action="run-admin-cleanup">
            ${t("admin.cleanup.run_now")}
          </button>
        </div>
      </form>
    </section>
  `;
}

function renderTimeoutsSettingsPanel(timeoutSettings = null) {
  const settings = timeoutSettings || {};

  const defaultSeconds = settings.default_seconds ?? 10;
  const realdebridSeconds = settings.realdebrid_seconds ?? 60;
  const alldebridSeconds = settings.alldebrid_seconds ?? 8;

  // TODO V3/backlog: Advanced timeout settings intentionally hidden for now.
  // Future sections: Provider HTTP timeouts, Destination timeouts, Worker/job timeouts.

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="timeouts" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.tab.timeouts")}</h3>
          <p class="muted">${t("admin.timeouts.subtitle")}</p>
        </div>
        <span class="badge badge-ready">${t("admin.timeouts.configured")}</span>
      </div>

      <div id="admin-timeouts-feedback" hidden></div>

      <form id="admin-timeouts-form" class="form-grid">
        <div class="timeout-setting-grid">
          <label class="timeout-setting-card">
            <span class="timeout-setting-label">${t("admin.timeouts.default_seconds")}</span>
            <div class="timeout-input-row">
              <input name="default_seconds" type="number" min="0" max="3600" value="${html(defaultSeconds)}" required />
              <span class="timeout-input-unit">${t("admin.timeouts.unit_seconds")}</span>
            </div>
          </label>

          <label class="timeout-setting-card">
            <span class="timeout-setting-label">${t("admin.timeouts.realdebrid_seconds")}</span>
            <div class="timeout-input-row">
              <input name="realdebrid_seconds" type="number" min="0" max="3600" value="${html(realdebridSeconds)}" required />
              <span class="timeout-input-unit">${t("admin.timeouts.unit_seconds")}</span>
            </div>
          </label>

          <label class="timeout-setting-card">
            <span class="timeout-setting-label">${t("admin.timeouts.alldebrid_seconds")}</span>
            <div class="timeout-input-row">
              <input name="alldebrid_seconds" type="number" min="0" max="3600" value="${html(alldebridSeconds)}" required />
              <span class="timeout-input-unit">${t("admin.timeouts.unit_seconds")}</span>
            </div>
          </label>
        </div>

        <div class="timeout-form-footer">
          <button type="submit" class="btn btn-primary">${t("admin.timeouts.save")}</button>
        </div>
      </form>
    </section>
  `;
}

function renderMaintenanceStatusPanel(maintenanceStatus = null) {
  const status = maintenanceStatus || {};
  const app = status.app || {};
  const database = status.database || {};
  const disk = status.disk || {};
  const paths = Array.isArray(status.paths) ? status.paths : [];

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="maintenance" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.tab.maintenance")}</h3>
          <p class="muted">${t("admin.maintenance.subtitle")}</p>
        </div>

        <button type="button" class="btn" data-action="refresh-admin-maintenance">
          ${t("admin.maintenance.refresh")}
        </button>
      </div>

      <div id="admin-maintenance-feedback" hidden></div>

      <div class="detail-block">
        <h4>${t("admin.maintenance.group_application")}</h4>
        <div class="admin-placeholder-grid">
          ${renderMaintenanceCheck(
            t("admin.maintenance.global_status"),
            Boolean(status.ok),
            status.generated_at
              ? `${t("admin.maintenance.generated_at")} ${formatDate(status.generated_at)}`
              : t("admin.maintenance.not_loaded")
          )}

          ${renderMaintenanceCheck(
            t("admin.maintenance.app_version"),
            true,
            `${app.name || "link2nas"} ${app.version || "unknown"} — debug: ${app.debug ? t("admin.maintenance.debug_yes") : t("admin.maintenance.debug_no")}`
          )}

          ${renderMaintenanceCheck(
            t("admin.maintenance.public_url"),
            Boolean(app.public_base_url),
            app.public_base_url || t("admin.maintenance.public_url_not_set")
          )}
        </div>
      </div>

      <div class="detail-block">
        <h4>${t("admin.maintenance.group_infrastructure")}</h4>
        <div class="admin-placeholder-grid">
          ${renderMaintenanceCheck(
            t("admin.maintenance.database"),
            Boolean(database.ok),
            `${database.backend || "unknown"} — ${database.message || ""}`
          )}

          ${renderMaintenanceCheck(
            t("admin.maintenance.disk_space"),
            Boolean(disk.ok),
            `${formatBytes(disk.free_bytes)} ${t("admin.maintenance.disk_free_label")} / ${formatBytes(disk.total_bytes)} — ${disk.percent_free ?? 0}% ${t("admin.maintenance.disk_free_pct")}`
          )}
        </div>
      </div>

      <div class="detail-block">
        <h4>${t("admin.maintenance.directories")}</h4>
        <div class="admin-placeholder-grid">
          ${
            paths.length
              ? paths.map((item) => renderMaintenanceCheck(
                  `${item.name}${item.required ? "" : ` ${t("admin.maintenance.optional")}`}`,
                  Boolean(item.ok),
                  `${item.path || "—"} — ${item.message || ""}`
                )).join("")
              : `<p class="muted">${t("admin.maintenance.no_directories")}</p>`
          }
        </div>
      </div>
    </section>
  `;
}

function renderRuntimeSettingsPanel(runtimeSettings = null) {
  const dispatcher = runtimeSettings?.notifications?.dispatcher || {};
  const orchestrator = runtimeSettings?.jobs?.orchestrator || {};
  const localWorker = runtimeSettings?.downloads?.local_worker || {};

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="runtime" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.tab.runtime")}</h3>
          <p class="muted">${t("admin.runtime.subtitle")}</p>
        </div>

        <span class="badge ${dispatcher.enabled ? "badge-ready" : ""}">
          ${t(dispatcher.enabled ? "admin.runtime.badge_active" : "admin.runtime.badge_partial")}
        </span>
      </div>

      <div id="admin-runtime-feedback" hidden></div>

      <form id="admin-runtime-form" class="form-grid">

        <section class="detail-block">
          <h4>${t("admin.runtime.dispatcher_title")}</h4>

          <label class="checkbox-row">
            <input
              type="checkbox"
              name="notification_dispatcher_enabled"
              ${dispatcher.enabled ? "checked" : ""}
            />
            <span>${t("admin.runtime.dispatcher_enable")}</span>
          </label>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.dispatcher_interval")}</span>
              <div class="security-input-row">
                <input
                  name="notification_dispatcher_interval_seconds"
                  type="number"
                  min="1"
                  max="3600"
                  value="${html(dispatcher.interval_seconds ?? 60)}"
                  required
                />
                <span class="security-input-unit">${t("admin.runtime.unit_seconds")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.dispatcher_limit")}</span>
              <div class="security-input-row">
                <input
                  name="notification_dispatcher_limit"
                  type="number"
                  min="1"
                  max="200"
                  value="${html(dispatcher.limit ?? 25)}"
                  required
                />
              </div>
            </label>
          </div>

          <div class="kv-grid">
            <div class="kv-item">
              <strong>${t("admin.runtime.dispatcher_last_run")}</strong>
              <div>${dispatcher.last_run_at ? html(formatDate(dispatcher.last_run_at)) : "—"}</div>
            </div>

            <div class="kv-item">
              <strong>${t("admin.runtime.dispatcher_last_error")}</strong>
              <div>${dispatcher.last_error ? html(dispatcher.last_error) : "—"}</div>
            </div>
          </div>

          <details class="detail-block">
            <summary>${t("admin.runtime.dispatcher_last_result")}</summary>
            <pre>${renderJsonBlock(dispatcher.last_result)}</pre>
          </details>

          <div class="admin-form-actions">
            <button type="button" class="btn" data-action="run-notification-dispatcher-now">
              ${t("admin.runtime.dispatcher_run_now")}
            </button>

            <button type="button" class="btn" data-action="refresh-notification-dispatcher-status">
              ${t("admin.runtime.dispatcher_refresh")}
            </button>
          </div>
        </section>

        <section class="detail-block">
          <h4>${t("admin.runtime.orchestrator_title")}</h4>

          <label class="checkbox-row">
            <input
              type="checkbox"
              name="jobs_orchestrator_enabled"
              ${orchestrator.enabled ? "checked" : ""}
            />
            <span>${t("admin.runtime.orchestrator_enable")}</span>
          </label>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.orchestrator_interval")}</span>
              <div class="security-input-row">
                <input
                  name="jobs_orchestrator_interval_seconds"
                  type="number"
                  min="1"
                  max="3600"
                  value="${html(orchestrator.interval_seconds ?? 5)}"
                  required
                />
                <span class="security-input-unit">${t("admin.runtime.unit_seconds")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.orchestrator_max_jobs")}</span>
              <div class="security-input-row">
                <input
                  name="jobs_orchestrator_max_jobs_per_run"
                  type="number"
                  min="1"
                  max="500"
                  value="${html(orchestrator.max_jobs_per_run ?? 25)}"
                  required
                />
              </div>
            </label>
          </div>

          <div class="admin-checkbox-grid">
            <label class="checkbox-row">
              <input
                type="checkbox"
                name="jobs_orchestrator_auto_refresh_enabled"
                ${orchestrator.auto_refresh_enabled ? "checked" : ""}
              />
              <span>${t("admin.runtime.orchestrator_auto_refresh")}</span>
            </label>

            <label class="checkbox-row">
              <input
                type="checkbox"
                name="jobs_orchestrator_auto_unrestrict_enabled"
                ${orchestrator.auto_unrestrict_enabled ? "checked" : ""}
              />
              <span>${t("admin.runtime.orchestrator_auto_unrestrict")}</span>
            </label>

            <label class="checkbox-row">
              <input
                type="checkbox"
                name="jobs_orchestrator_auto_send_destination_enabled"
                ${orchestrator.auto_send_destination_enabled ? "checked" : ""}
              />
              <span>${t("admin.runtime.orchestrator_auto_send")}</span>
            </label>
          </div>
        </section>

        <section class="detail-block">
          <h4>${t("admin.runtime.worker_title")}</h4>

          <label class="checkbox-row">
            <input
              type="checkbox"
              name="local_worker_enabled"
              ${localWorker.enabled ? "checked" : ""}
            />
            <span>${t("admin.runtime.worker_enable")}</span>
          </label>

          <div class="security-setting-grid">
            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.worker_poll_interval")}</span>
              <div class="security-input-row">
                <input
                  name="local_worker_poll_interval_seconds"
                  type="number"
                  min="1"
                  max="3600"
                  value="${html(localWorker.poll_interval_seconds ?? 5)}"
                  required
                />
                <span class="security-input-unit">${t("admin.runtime.unit_seconds")}</span>
              </div>
            </label>

            <label class="security-setting-card">
              <span class="security-setting-label">${t("admin.runtime.worker_max_concurrent")}</span>
              <div class="security-input-row">
                <input
                  name="local_worker_max_concurrent_downloads"
                  type="number"
                  min="1"
                  max="20"
                  value="${html(localWorker.max_concurrent_downloads ?? 1)}"
                  required
                />
              </div>
            </label>
          </div>
        </section>

        <div class="admin-form-actions">
          <button type="submit" class="btn btn-primary">
            ${t("admin.runtime.save")}
          </button>
        </div>
      </form>
    </section>
  `;
}

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
