import { t } from "../../i18n/index.js";
import { state } from "../../state.js";
import {
  html,
  formatProviderType,
  formatProfileName,
  formatExpiration,
} from "./utils.js";

export function renderProvidersHtml(providers = []) {
  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.providers.title")}</h2>
        <p class="muted">${t("settings.providers.subtitle")}</p>
      </div>
    </div>

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
    </form>

    <div id="provider-feedback" hidden></div>

    <div class="settings-subsection-header">
      <h3>${t("settings.providers.configured_title")}</h3>
    </div>

    <div class="settings-list">
      ${
        providers.length
          ? providers.map((p) => `
              <article class="job-card provider-card${p.is_default ? " is-default" : ""}">
                <div class="provider-main">
                  <div class="provider-title-row">
                    <strong>${html(formatProfileName(p, formatProviderType(p.provider_type || p.provider_name)))}</strong>
                    ${p.is_default ? `<span class="provider-default-badge">${t("settings.providers.badge_default")}</span>` : ""}
                  </div>
                  <div class="provider-meta">
                    <span class="meta-pill">${html(formatProviderType(p.provider_type || p.provider_name))}</span>
                    ${p.is_enabled
                      ? `<span class="meta-pill is-success">${t("settings.providers.meta_enabled")}</span>`
                      : `<span class="meta-pill is-muted">${t("settings.providers.meta_disabled")}</span>`
                    }
                    ${p.has_api_key
                      ? `<span class="meta-pill">${t("settings.providers.meta_key_present")}</span>`
                      : `<span class="meta-pill is-warning">${t("settings.providers.meta_key_absent")}</span>`
                    }
                    ${p.account_expires_at
                      ? `<span class="meta-pill">${t("settings.providers.meta_expires_at", { date: formatExpiration(p.account_expires_at) })}</span>`
                      : `<span class="meta-pill is-muted">${t("settings.providers.meta_expiry_unknown")}</span>`
                    }
                  </div>
                </div>

                <div class="provider-actions inline-actions">
                  <div class="provider-toggles">
                    <label class="provider-toggle">
                      <input
                        type="checkbox"
                        data-settings-action="toggle-provider-enabled"
                        data-provider-id="${html(p.id)}"
                        data-provider-type="${html(p.provider_type || p.provider_name)}"
                        data-provider-name="${html(p.name)}"
                        data-is-default="${p.is_default ? "1" : "0"}"
                        ${p.is_enabled ? "checked" : ""}
                      />
                      <span>${t("settings.providers.meta_enabled")}</span>
                    </label>
                    <label class="provider-toggle">
                      <input
                        type="checkbox"
                        data-settings-action="set-provider-default"
                        data-provider-id="${html(p.id)}"
                        data-provider-type="${html(p.provider_type || p.provider_name)}"
                        data-provider-name="${html(p.name)}"
                        ${p.is_default ? "checked" : ""}
                      />
                      <span>${t("settings.providers.badge_default")}</span>
                    </label>
                  </div>
                  <button type="button" class="btn" data-settings-action="edit-provider" data-provider-id="${html(p.id)}">${t("common.edit")}</button>
                  <button type="button" class="btn" data-settings-action="test-provider" data-provider-id="${html(p.id)}">${t("common.test")}</button>
                  <button type="button" class="btn btn-danger" data-settings-action="delete-provider" data-provider-id="${html(p.id)}">${t("common.delete")}</button>
                </div>
              </article>
            `).join("")
          : `<p class="muted">${t("settings.providers.empty")}</p>`
      }
    </div>
  `;
}

export function renderProvidersPanel(providers = []) {
  const container = document.getElementById("providers-panel");
  if (!container) return;
  container.innerHTML = renderProvidersHtml(providers);
}

export function fillProviderForm(provider) {
  const form = document.getElementById("provider-form");
  if (!form || !provider) return;

  form.provider_config_id.value = provider.id || "";
  form.name.value = provider.name || "";
  form.provider_type.value = provider.provider_type || provider.provider_name;
  form.api_key.value = "";
  form.is_enabled.checked = Boolean(provider.is_enabled);
  form.is_default.checked = Boolean(provider.is_default);

  form.querySelector("button[type='submit']").textContent = t("settings.providers.update");
  form.querySelector("[data-settings-action='cancel-provider-edit']").hidden = false;
}
