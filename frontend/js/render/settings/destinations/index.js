import { t } from "../../../i18n/index.js";
import { state } from "../../../state.js";
import { renderDestinationForm } from "./form.js";
import { renderDestinationCard } from "./card.js";

export function renderDestinationsHtml(destinations = [], canUseLocalSpace = true) {
  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.destinations.title")}</h2>
        <p class="muted">${t("settings.destination.subtitle")}</p>
      </div>
    </div>

    ${!canUseLocalSpace ? `<p class="muted">${t("settings.destinations.local_not_allowed")}</p>` : ""}

    ${renderDestinationForm(canUseLocalSpace)}

    <div id="destination-feedback" hidden></div>

    <div class="settings-subsection-header">
      <h3>${t("settings.destinations.configured_title")}</h3>
    </div>

    <div class="settings-list">
      ${
        destinations.length
          ? destinations.map(renderDestinationCard).join("")
          : `<p class="muted">${t("settings.destinations.empty")}</p>`
      }
    </div>
  `;
}

export function renderDestinationsPanel(destinations = []) {
  const container = document.getElementById("destinations-panel");
  if (!container) return;
  container.innerHTML = renderDestinationsHtml(destinations, Boolean(state.currentUser?.can_use_local_space));
  updateDestinationFields();
}

export function updateDestinationFields() {
  const select = document.getElementById("destination-name");
  const destinationName = select?.value || "synology";

  document.querySelectorAll("[data-destination-field]").forEach((field) => {
    field.hidden = field.dataset.destinationField !== destinationName;
  });
}

export function fillDestinationForm(destination) {
  const form = document.getElementById("destination-form");
  if (!form || !destination) return;

  form.destination_config_id.value = destination.id || "";
  form.name.value = destination.name || "";
  form.destination_type.value = destination.destination_type || destination.destination_name;
  form.is_enabled.checked = Boolean(destination.is_enabled);
  form.is_default.checked = Boolean(destination.is_default);

  const cfg = destination.config || {};

  if (form.base_path) form.base_path.value = cfg.base_path || "";
  if (form.synology_url) form.synology_url.value = cfg.synology_url || "";
  if (form.username) form.username.value = cfg.username || "";
  if (form.password) form.password.value = "";
  if (form.destination_base) form.destination_base.value = cfg.destination_base || "";
  if (form.verify_ssl) form.verify_ssl.checked = Boolean(cfg.verify_ssl);

  updateDestinationFields();

  form.querySelector("button[type='submit']").textContent = t("settings.destinations.update");
  form.querySelector("[data-settings-action='cancel-destination-edit']").hidden = false;
}
