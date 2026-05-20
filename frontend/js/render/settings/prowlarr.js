import { t } from "../../i18n/index.js";
import { html } from "./utils.js";

export function renderProwlarrSettingsHtml(integrationSettings = {}, apiKeys = []) {
  const settings = {
    prowlarr_enabled: false,
    prowlarr_url: "",
    prowlarr_open_mode: "both",
    home_page: "jobs",
    ...(integrationSettings || {}),
  };

  const prowlarrEnabled = Boolean(settings.prowlarr_enabled);
  const prowlarrUrl = String(settings.prowlarr_url || "");
  const prowlarrOpenMode = settings.prowlarr_open_mode || "both";
  const homePage = settings.home_page || "jobs";

  const hasQbtKey = apiKeys.some(
    (k) => k.is_active && Array.isArray(k.scopes) && k.scopes.includes("qbittorrent:write")
  );

  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.prowlarr.title")}</h2>
        <p class="muted">${t("settings.prowlarr.settings_subtitle")}</p>
      </div>
    </div>

    <form id="prowlarr-settings-form" class="form-grid">
      ${prowlarrEnabled && !hasQbtKey ? `
        <div class="prowlarr-no-key-warning">
          ${t("settings.prowlarr.no_qbt_key_warning")}
        </div>
      ` : ""}

      <label class="checkbox-row${!hasQbtKey ? " prowlarr-checkbox-disabled" : ""}">
        <input
          type="checkbox"
          name="prowlarr_enabled"
          ${prowlarrEnabled && hasQbtKey ? "checked" : ""}
          ${!hasQbtKey ? "disabled" : ""}
        />
        <span>${t("settings.prowlarr.enable_integration")}</span>
      </label>

      ${!hasQbtKey ? `
        <p class="prowlarr-no-key-hint">
          ${t("settings.prowlarr.no_qbt_key_hint")}
          <button type="button" class="btn-link" data-settings-action="show-prowlarr-api-key-modal">
            ${t("settings.prowlarr.no_qbt_key_action")}
          </button>
        </p>
      ` : ""}

      <label>
        <span>${t("settings.prowlarr.url_label")}</span>
        <input
          name="prowlarr_url"
          type="url"
          placeholder="http://prowlarr.local:9696"
          value="${html(prowlarrUrl)}"
        />
      </label>

      <label>
        <span>${t("settings.prowlarr.open_mode_label")}</span>
        <select name="prowlarr_open_mode">
          <option value="iframe" ${prowlarrOpenMode === "iframe" ? "selected" : ""}>
            ${t("settings.prowlarr.open_mode_iframe")}
          </option>
          <option value="new_tab" ${prowlarrOpenMode === "new_tab" ? "selected" : ""}>
            ${t("settings.prowlarr.open_mode_new_tab")}
          </option>
          <option value="both" ${prowlarrOpenMode === "both" ? "selected" : ""}>
            ${t("settings.prowlarr.open_mode_both")}
          </option>
        </select>
      </label>

      <label>
        <span>${t("settings.prowlarr.home_page_label")}</span>
        <select name="home_page">
          <option value="jobs" ${homePage === "jobs" ? "selected" : ""}>${t("settings.prowlarr.home_page_jobs")}</option>
          <option value="control-center" ${homePage === "control-center" ? "selected" : ""}>${t("settings.prowlarr.home_page_control_center")}</option>
          <option value="prowlarr" ${homePage === "prowlarr" ? "selected" : ""}>${t("settings.prowlarr.home_page_prowlarr")}</option>
        </select>
        <p class="muted">
          ${t("settings.prowlarr.home_page_hint")}
        </p>
      </label>

      <div class="prowlarr-help detail-block">
        <h3>${t("settings.prowlarr.config_help_title")}</h3>
        <p class="prowlarr-help-intro">${t("settings.prowlarr.config_help_intro")}</p>

        <div class="prowlarr-help-grid">
          <div class="prowlarr-help-card">
            <span class="prowlarr-help-label">${t("settings.prowlarr.config_client_type")}</span>
            <span class="prowlarr-help-value">qBittorrent</span>
          </div>

          <div class="prowlarr-help-card">
            <span class="prowlarr-help-label">${t("settings.prowlarr.config_host")}</span>
            <span class="prowlarr-help-value code-block">${html(window.location.origin)}</span>
          </div>

          <div class="prowlarr-help-card">
            <span class="prowlarr-help-label">${t("settings.prowlarr.config_api_key")}</span>
            <span class="prowlarr-help-value">
              ${t("settings.prowlarr.config_api_key_hint")} <span class="code-inline">qbittorrent:write</span>
            </span>
          </div>

          <div class="prowlarr-help-card">
            <span class="prowlarr-help-label">${t("settings.prowlarr.config_category")}</span>
            <span class="prowlarr-help-value code-block">prowlarr</span>
          </div>
        </div>

        <div class="prowlarr-help-note">
          ${t("settings.prowlarr.no_credentials")}
        </div>
      </div>

      <button class="btn btn-primary" type="submit">
        ${t("settings.prowlarr.save")}
      </button>
    </form>
  `;
}
