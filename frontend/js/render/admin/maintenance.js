import { formatDate } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { formatBytes, renderMaintenanceCheck } from "./utils.js";

export function renderMaintenanceStatusPanel(maintenanceStatus = null) {
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
