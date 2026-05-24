import { t } from "../../../i18n/index.js";
import {
  html,
  formatDestinationType,
  formatProfileName,
} from "../utils.js";
import { renderDestinationDetails } from "./details.js";

export function renderDestinationCard(d) {
  return `
              <article class="job-card destination-card${d.is_default ? " is-default" : ""}">
                <div class="destination-main">
                  <div class="destination-title-row">
                    <strong>${html(formatProfileName(d, formatDestinationType(d.destination_type || d.destination_name)))}</strong>
                    ${d.is_default ? `<span class="destination-default-badge">${t("settings.destinations.badge_default")}</span>` : ""}
                  </div>
                  <div class="destination-meta">
                    <span class="meta-pill">${html(formatDestinationType(d.destination_type || d.destination_name))}</span>
                    ${d.is_enabled
                      ? `<span class="meta-pill is-success">${t("settings.destinations.meta_enabled")}</span>`
                      : `<span class="meta-pill is-muted">${t("settings.destinations.meta_disabled")}</span>`
                    }
                    ${d.is_default ? `<span class="meta-pill">${t("settings.destinations.badge_default")}</span>` : ""}
                  </div>
                  ${renderDestinationDetails(d)}
                </div>
                <div class="destination-actions inline-actions">
                  <div class="destination-toggles">
                    <label class="destination-toggle">
                      <input
                        type="checkbox"
                        data-settings-action="toggle-destination-enabled"
                        data-destination-id="${html(d.id)}"
                        ${d.is_enabled ? "checked" : ""}
                      />
                      <span>${t("settings.destinations.meta_enabled")}</span>
                    </label>
                    <label class="destination-toggle">
                      <input
                        type="checkbox"
                        data-settings-action="set-destination-default"
                        data-destination-id="${html(d.id)}"
                        ${d.is_default ? "checked" : ""}
                      />
                      <span>${t("settings.destinations.badge_default")}</span>
                    </label>
                  </div>
                  <button type="button" class="btn" data-settings-action="edit-destination" data-destination-id="${html(d.id)}">${t("common.edit")}</button>
                  <button type="button" class="btn" data-settings-action="test-destination" data-destination-id="${html(d.id)}">${t("common.test")}</button>
                  <button type="button" class="btn btn-danger" data-settings-action="delete-destination" data-destination-id="${html(d.id)}">${t("common.delete")}</button>
                </div>
              </article>
            `;
}
