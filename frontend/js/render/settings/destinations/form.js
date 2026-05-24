import { t } from "../../../i18n/index.js";

export function renderDestinationForm(canUseLocalSpace = true) {
  return `
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
  `;
}
