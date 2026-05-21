import { t } from "../../i18n/index.js";
import { state } from "../../state.js";
import { escapeHtml, isTruthy } from "./utils.js";

function formatDestinationType(destinationType) {
  const value = String(destinationType || "").trim().toLowerCase();

  if (value === "synology" || value === "nas") return "NAS Synology";
  if (value === "local") return "Local";

  return destinationType || "-";
}

export function formatDestinationProfile(destination) {
  const name = String(destination?.name || destination?.destination_profile_name || "").trim();
  const type = formatDestinationType(destination?.destination_type || destination?.destination_name);

  return name ? `${name} (${type})` : type;
}

export function getRealDestinations() {
  const canUseLocalSpace = Boolean(state.currentUser?.can_use_local_space);
  return (state.destinations || []).filter((destination) => {
    const type = destination.destination_type || destination.destination_name;
    if (!canUseLocalSpace && type === "local") return false;
    return isTruthy(destination.is_enabled) && ["synology", "nas", "local"].includes(type);
  });
}

function getDefaultDestinationId(destinations) {
  const defaultDestination = destinations.find((destination) => destination.is_default);
  return defaultDestination?.id || destinations[0]?.id || "";
}

export function renderDestinationSelect(destinations) {
  const defaultDestinationId = getDefaultDestinationId(destinations);
  const defaultDestination = destinations.find((destination) => destination.id === defaultDestinationId) || destinations[0];

  return `
    <div id="create-destination-select-wrap" hidden>
      ${
        destinations.length === 1
          ? `
            <input type="hidden" name="destination_config_id" value="${escapeHtml(defaultDestinationId)}" />
            <div class="readonly-selection">
              <span class="muted">Destination</span>
              <strong>${escapeHtml(formatDestinationProfile(defaultDestination))}</strong>
            </div>
          `
          : destinations.length > 1
            ? `
              <label>
                <span>Destination</span>
                <select name="destination_config_id">
                  ${destinations.map((destination) => `
                    <option
                      value="${escapeHtml(destination.id)}"
                      ${destination.id === defaultDestinationId ? "selected" : ""}
                    >
                      ${escapeHtml(formatDestinationProfile(destination))}
                      ${destination.is_default ? ` — ${t("settings.providers.label_default")}` : ""}
                    </option>
                  `).join("")}
                </select>
              </label>
            `
            : `
              <div class="empty-state">
                <strong>${t("form.no_destination")}</strong>
                <p class="muted">${t("form.no_destination_hint")}</p>
              </div>
            `
      }
    </div>
  `;
}
