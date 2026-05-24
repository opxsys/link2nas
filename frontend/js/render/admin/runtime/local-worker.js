import { t } from "../../../i18n/index.js";
import { html } from "../utils.js";

export function renderLocalWorkerRuntimeSection(localWorker) {
  return `
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
        </section>`;
}
