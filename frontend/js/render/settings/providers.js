import { t } from "../../i18n/index.js";
import { state } from "../../state.js";
import { renderProviderForm } from "./providers/form.js";
import { renderProviderCard } from "./providers/card.js";

export function renderProvidersHtml(providers = []) {
  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.providers.title")}</h2>
        <p class="muted">${t("settings.providers.subtitle")}</p>
      </div>
    </div>

    ${renderProviderForm()}

    <div id="provider-feedback" hidden></div>

    <div class="settings-subsection-header">
      <h3>${t("settings.providers.configured_title")}</h3>
    </div>

    <div class="settings-list">
      ${
        providers.length
          ? providers.map(renderProviderCard).join("")
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
