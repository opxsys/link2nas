import { t } from "../../i18n/index.js";
import { html } from "./utils.js";

export function renderGeneralSettingsPanel(generalSettings = null) {
  const settings = generalSettings || {};

  return `
    <section class="admin-section-card admin-tab-panel" data-admin-panel="general" hidden>
      <div class="admin-section-title">
        <div>
          <h3>${t("admin.general.title")}</h3>
          <p class="muted">${t("admin.general.subtitle")}</p>
        </div>
        <span class="badge badge-ready">${t("admin.general.configured")}</span>
      </div>

      <div id="admin-general-feedback" hidden></div>

      <form id="admin-general-form" class="form-grid">
        <label>
          <span>${t("admin.general.app_name_label")}</span>
          <input name="app_name" type="text" value="${html(settings.app_name || "")}" />
        </label>

        <label>
          <span>${t("admin.general.app_tagline_label")}</span>
          <input name="app_tagline" type="text" value="${html(settings.app_tagline || "")}" />
        </label>

        <div class="detail-block">
          <h4>${t("admin.general.public_url_title")}</h4>
          <label>
            <span>${t("admin.general.public_url_label")}</span>
            <input
              name="public_base_url"
              type="url"
              value="${html(settings.public_base_url || "")}"
              placeholder="https://link2nas.example.com"
            />
          </label>
          <p class="muted">${t("admin.general.public_url_hint")}</p>
          ${settings.effective_public_base_url
            ? `<p class="muted">${t("admin.general.effective_public_url")} : <strong>${html(settings.effective_public_base_url)}</strong></p>`
            : ""}
        </div>

        <div class="admin-form-actions">
          <button type="submit" class="btn btn-primary">${t("admin.general.save")}</button>
        </div>
      </form>
    </section>
  `;
}
