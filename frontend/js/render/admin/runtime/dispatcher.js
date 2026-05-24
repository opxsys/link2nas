import { formatDate } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { html, renderJsonBlock } from "../utils.js";

export function renderDispatcherRuntimeSection(dispatcher) {
  return `
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
        </section>`;
}
