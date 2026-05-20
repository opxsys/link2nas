import { t } from "../../i18n/index.js";
import { html, formatExpiration } from "./utils.js";

export function renderApiKeysHtml(apiKeys = []) {
  const scopeOptions = [
    ["qbittorrent:write", "qBittorrent / Prowlarr", false],
    ["jobs:create", "Créer des jobs", true],
    ["jobs:read", "Lire les jobs", true],
    ["scripts", "Scripts externes", true],
    ["extension", "Extension navigateur", true],
  ];

  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.api_keys.title")}</h2>
        <p class="muted">${t("settings.api_keys.subtitle")}</p>
      </div>
    </div>

    <form id="api-key-form" class="form-grid">
      <label>
        <span>${t("settings.api_keys.name_label")}</span>
        <input name="name" placeholder="${t("settings.api_keys.name_placeholder")}" required />
      </label>

      <fieldset class="api-key-scopes">
        <legend>${t("settings.api_keys.scopes_label")}</legend>

        ${scopeOptions.map(([value, label, comingSoon]) => `
          <label class="checkbox-row${comingSoon ? " is-disabled" : ""}">
            <input
              type="checkbox"
              name="scope"
              value="${html(value)}"
              ${value === "qbittorrent:write" ? "checked" : ""}
              ${comingSoon ? "disabled" : ""}
            />
            <span>
              ${html(label)} <span class="muted">(${html(value)})</span>
              ${comingSoon ? `<span class="scope-coming-soon">${t("settings.api_keys.scope_coming_soon")}</span>` : ""}
            </span>
          </label>
        `).join("")}
      </fieldset>

      <button class="btn btn-primary" type="submit">${t("settings.api_keys.create")}</button>
    </form>

    <div id="api-key-feedback" hidden></div>

    <div class="settings-subsection-header">
      <h3>${t("settings.api_keys.configured_title")}</h3>
    </div>

    <div class="settings-list">
      ${
        apiKeys.length
          ? apiKeys.map((key) => `
              <article class="job-card api-key-card">
                <div class="api-key-main">
                  <div class="api-key-title-row">
                    <strong>${html(key.name)}</strong>
                    ${key.is_active
                      ? `<span class="meta-pill is-success">${t("settings.api_keys.meta_active")}</span>`
                      : `<span class="meta-pill is-muted">${t("settings.api_keys.meta_revoked")}</span>`
                    }
                  </div>

                  <div class="api-key-meta">
                    <span class="meta-pill">${html(key.key_prefix)}</span>
                    ${Array.isArray(key.scopes) && key.scopes.length
                      ? key.scopes.map((s) => `<span class="meta-pill is-muted">${html(s)}</span>`).join("")
                      : ""
                    }
                  </div>

                  <div class="api-key-details">
                    <div><span class="api-key-detail-label">${t("settings.api_keys.detail_created")}</span><span>${html(formatExpiration(key.created_at))}</span></div>
                    <div><span class="api-key-detail-label">${t("settings.api_keys.detail_last_used")}</span><span>${key.last_used_at ? html(formatExpiration(key.last_used_at)) : t("settings.api_keys.detail_never")}</span></div>
                    ${key.last_used_scope ? `<div><span class="api-key-detail-label">${t("settings.api_keys.detail_last_scope")}</span><span>${html(key.last_used_scope)}</span></div>` : ""}
                    ${key.revoked_at ? `<div><span class="api-key-detail-label">${t("settings.api_keys.detail_revoked_at")}</span><span>${html(formatExpiration(key.revoked_at))}</span></div>` : ""}
                  </div>
                </div>

                <div class="api-key-actions inline-actions">
                  ${
                    key.is_active
                      ? `<button type="button" class="btn" data-settings-action="revoke-api-key" data-api-key-id="${html(key.id)}">${t("settings.api_keys.revoke")}</button>`
                      : ""
                  }
                  <button type="button" class="btn btn-danger" data-settings-action="delete-api-key" data-api-key-id="${html(key.id)}">
                    ${t("common.delete")}
                  </button>
                </div>
              </article>
            `).join("")
          : `<p class="muted">${t("settings.api_keys.empty")}</p>`
      }
    </div>
  `;
}
