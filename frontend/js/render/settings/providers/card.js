import { t } from "../../../i18n/index.js";
import { html, formatProviderType, formatProfileName, formatExpiration } from "../utils.js";

export function renderProviderCard(p) {
  return `
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
            `;
}
