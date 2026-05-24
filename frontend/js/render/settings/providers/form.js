import { t } from "../../../i18n/index.js";

export function renderProviderForm() {
  return `
    <form id="provider-form" class="form-grid">
      <input type="hidden" name="provider_config_id" />

      <label>
        <span>${t("settings.providers.form_name")}</span>
        <input name="name" placeholder="${t("settings.providers.form_name_placeholder")}" required />
      </label>

      <label>
        <span>${t("settings.providers.form_type")}</span>
        <select name="provider_type" required>
          <option value="realdebrid">RealDebrid</option>
          <option value="alldebrid">AllDebrid</option>
        </select>
      </label>

      <div>
        <label>
          <span>${t("settings.providers.form_api_key")}</span>
          <input type="password" name="api_key" />
        </label>
        <p class="form-hint muted">${t("settings.providers.form_api_key_hint")}</p>
      </div>

      <div class="provider-form-footer">
        <div class="provider-form-flags">
          <label class="checkbox-row">
            <input type="checkbox" name="is_enabled" checked />
            <span>${t("settings.providers.meta_enabled")}</span>
          </label>
          <label class="checkbox-row">
            <input type="checkbox" name="is_default" checked />
            <span>${t("settings.providers.badge_default")}</span>
          </label>
        </div>
        <div class="form-actions provider-form-actions">
          <button type="submit" class="btn btn-primary">${t("settings.providers.save")}</button>
          <button type="button" class="btn" data-settings-action="cancel-provider-edit" hidden>
            ${t("common.cancel")}
          </button>
        </div>
      </div>
    </form>`;
}
