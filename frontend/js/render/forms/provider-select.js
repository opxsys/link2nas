import { t } from "../../i18n/index.js";
import { state } from "../../state.js";
import { escapeHtml, isTruthy } from "./utils.js";

function formatProviderType(providerType) {
  const value = String(providerType || "").trim().toLowerCase();

  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";

  return providerType || "-";
}

function formatProviderProfile(provider) {
  const name = String(provider?.name || provider?.provider_profile_name || "").trim();
  const type = formatProviderType(provider?.provider_type || provider?.provider_name);

  return name ? `${name} (${type})` : type;
}

function getDefaultProviderId(providers) {
  const defaultProvider = providers.find((provider) => provider.is_default);
  return defaultProvider?.id || providers[0]?.id || "";
}

export function getEnabledProviders() {
  return (state.providers || []).filter((provider) => isTruthy(provider.is_enabled));
}

export function renderProviderSelect(providers) {
  if (!providers.length) {
    return `
      <div class="empty-state">
        <strong>${t("form.no_provider")}</strong>
        <p class="muted">${t("form.no_provider_hint")}</p>
      </div>
    `;
  }

  const defaultProviderId = getDefaultProviderId(providers);
  const defaultProvider = providers.find((provider) => provider.id === defaultProviderId) || providers[0];

  if (providers.length === 1) {
    return `
      <input type="hidden" name="provider_config_id" value="${escapeHtml(defaultProviderId)}" />
      <div class="readonly-selection">
        <span class="muted">Provider</span>
        <strong>${escapeHtml(formatProviderProfile(defaultProvider))}</strong>
      </div>
    `;
  }

  return `
    <label>
      <span>Provider</span>
      <select name="provider_config_id">
        ${providers.map((provider) => `
          <option
            value="${escapeHtml(provider.id)}"
            ${provider.id === defaultProviderId ? "selected" : ""}
          >
            ${escapeHtml(formatProviderProfile(provider))}
            ${provider.is_default ? ` — ${t("settings.providers.label_default")}` : ""}
          </option>
        `).join("")}
      </select>
    </label>
  `;
}
