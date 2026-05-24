import { t } from "../../../i18n/index.js";
import { state } from "../../../state.js";
import {
  html,
  formatDestinationType,
  formatProfileName,
} from "../utils.js";

export function renderDestinationsHtml(destinations = [], canUseLocalSpace = true) {
  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.destinations.title")}</h2>
        <p class="muted">${t("settings.destination.subtitle")}</p>
      </div>
    </div>

    ${!canUseLocalSpace ? `<p class="muted">${t("settings.destinations.local_not_allowed")}</p>` : ""}

    <form id="destination-form" class="form-grid">
      <input type="hidden" name="destination_config_id" />

      <label>
        <span>${t("settings.destinations.form_name")}</span>
        <input name="name" placeholder="${t("settings.destinations.form_name_placeholder")}" required />
      </label>

      <label>
        <span>${t("settings.destinations.form_type")}</span>
        <select name="destination_type" id="destination-name" required>
          ${canUseLocalSpace ? `<option value="local">${t("settings.destinations.form_type_local")}</option>` : ""}
          <option value="synology">${t("settings.destinations.form_type_synology")}</option>
        </select>
      </label>

      <div data-destination-field="local">
        <label>
          <span>${t("settings.destinations.form_base_path")}</span>
          <input type="text" name="base_path" placeholder="downloads" />
        </label>
        <p class="form-hint muted">${t("settings.destinations.form_base_path_hint")}</p>
      </div>

      <label data-destination-field="synology">
        <span>${t("settings.destinations.form_synology_url")}</span>
        <input type="text" name="synology_url" placeholder="http://nas.local:5000" />
      </label>

      <label data-destination-field="synology">
        <span>${t("settings.destinations.form_username")}</span>
        <input type="text" name="username" />
      </label>

      <div data-destination-field="synology">
        <label>
          <span>${t("settings.destinations.form_password")}</span>
          <input type="password" name="password" />
        </label>
        <p class="form-hint muted">${t("settings.destinations.form_password_hint")}</p>
      </div>

      <label data-destination-field="synology">
        <span>${t("settings.destinations.form_dest_base")}</span>
        <input type="text" name="destination_base" placeholder="downloads" />
      </label>
      <label class="checkbox-row" data-destination-field="synology">
        <input type="checkbox" name="verify_ssl" />
        <span>${t("settings.destinations.form_verify_ssl")}</span>
      </label>

      <div class="destination-form-footer">
        <div class="destination-form-flags">
          <label class="checkbox-row">
            <input type="checkbox" name="is_enabled" checked />
            <span>${t("settings.destinations.meta_enabled")}</span>
          </label>
          <label class="checkbox-row">
            <input type="checkbox" name="is_default" checked />
            <span>${t("settings.destinations.badge_default")}</span>
          </label>
        </div>
        <div class="form-actions destination-form-actions">
          <button type="submit" class="btn btn-primary">${t("settings.destinations.save")}</button>
          <button type="button" class="btn" data-settings-action="cancel-destination-edit" hidden>
            ${t("common.cancel")}
          </button>
        </div>
      </div>
    </form>

    <div id="destination-feedback" hidden></div>

    <div class="settings-subsection-header">
      <h3>${t("settings.destinations.configured_title")}</h3>
    </div>

    <div class="settings-list">
      ${
        destinations.length
          ? destinations.map((d) => `
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
                  ${(() => {
                    const cfg = d.config || {};
                    const type = d.destination_type || d.destination_name;
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
                  })()}
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
            `).join("")
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
