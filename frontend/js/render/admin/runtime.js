import { formatDate } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { html, renderJsonBlock } from "./utils.js";

export function renderRuntimeSettingsPanel(runtimeSettings = null) {
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
