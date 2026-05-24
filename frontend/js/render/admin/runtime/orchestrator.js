import { t } from "../../../i18n/index.js";
import { html } from "../utils.js";

export function renderOrchestratorRuntimeSection(orchestrator) {
  return `
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
        </section>`;
}
