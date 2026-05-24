import { t } from "../../../i18n/index.js";
import { html } from "../utils.js";

export function renderDestinationDetails(destination) {
  const cfg = destination.config || {};
  const type = destination.destination_type || destination.destination_name;
  if (type === "synology") {
    return `<div class="destination-details">
                        <div><span class="destination-detail-label">${t("settings.destinations.detail_url")}</span><span>${html(cfg.synology_url || "—")}</span></div>
                        <div><span class="destination-detail-label">${t("settings.destinations.detail_username")}</span><span>${html(cfg.username || "—")}</span></div>
                        <div><span class="destination-detail-label">${t("settings.destinations.detail_folder")}</span><span>${html(cfg.destination_base || "—")}</span></div>
                        <div><span class="destination-detail-label">${t("settings.destinations.detail_ssl")}</span><span>${cfg.verify_ssl ? t("common.yes") : t("common.no")}</span></div>
                        ${"has_password" in cfg ? `<div><span class="destination-detail-label">${t("settings.destinations.detail_password")}</span><span>${cfg.has_password ? t("settings.destinations.detail_password_present") : t("settings.destinations.detail_password_absent")}</span></div>` : ""}
                      </div>`;
  }
  return `<div class="destination-details">
                      <div><span class="destination-detail-label">${t("settings.destinations.detail_base_path")}</span><span>${html(cfg.base_path || "—")}</span></div>
                    </div>`;
}
