import { t } from "../../i18n/index.js";
import { html } from "./utils.js";

export function renderTimeoutsSettingsPanel(timeoutSettings = null) {
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
