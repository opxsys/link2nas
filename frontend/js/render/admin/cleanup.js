import { t } from "../../i18n/index.js";
import { html } from "./utils.js";

export function renderCleanupSettingsPanel(cleanupSettings = null) {
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
