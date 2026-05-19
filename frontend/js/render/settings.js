import { t } from "../i18n/index.js";
import { state } from "../state.js";

const VALID_SETTINGS_TABS = ["account", "providers", "destinations", "api_keys", "notifications", "prowlarr", "espace"];

function getActiveSettingsTab() {
  try {
    const stored = localStorage.getItem("settings_tab");
    return VALID_SETTINGS_TABS.includes(stored) ? stored : "account";
  } catch {
    return "account";
  }
}

function setActiveSettingsTab(tab) {
  try {
    localStorage.setItem("settings_tab", tab);
  } catch {
    // localStorage unavailable — state is ephemeral only
  }
}

function getActiveNotificationSubtab() {
  try {
    const stored = localStorage.getItem("notification_subtab");
    return stored === "rules" ? "rules" : "channels";
  } catch {
    return "channels";
  }
}

function setActiveNotificationSubtab(subtab) {
  try {
    localStorage.setItem("notification_subtab", subtab !== "rules" ? "channels" : "rules");
  } catch {}
}

function html(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function yesNo(value) {
  return value ? t("common.yes") : t("common.no");
}

function formatProviderType(providerType) {
  const value = String(providerType || "").trim().toLowerCase();
  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";
  return providerType || "—";
}

function formatDestinationType(destinationType) {
  const value = String(destinationType || "").trim().toLowerCase();
  if (value === "synology" || value === "nas") return "NAS Synology";
  if (value === "local") return "Local";
  return destinationType || "—";
}

function formatProfileName(item, fallbackType) {
  return String(item?.name || "").trim() || fallbackType || "Sans nom";
}

function formatExpiration(value) {
  if (!value) return "inconnue";

  const raw = String(value).trim();
  let date = null;

  if (/^\d+$/.test(raw)) {
    const timestamp = Number(raw);
    date = new Date(timestamp > 9999999999 ? timestamp : timestamp * 1000);
  } else {
    date = new Date(raw);
  }

  if (Number.isNaN(date.getTime())) {
    return raw;
  }

  return new Intl.DateTimeFormat(state.language || "fr", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function renderEmailStatus(me) {
  const isEmailVerified = Boolean(me?.email_verified);

  return `
    <article class="job-card">
      <strong>${t("settings.account.email_validation_title")}</strong>

      <div class="muted">
        ${t("settings.account.current_address")} : ${html(me?.email || "—")}
      </div>

      <div style="margin-top: 8px;">
        ${
          isEmailVerified
            ? `<span class="badge badge-ready">${t("settings.account.email_verified")}</span>`
            : `<span class="badge badge-failed">${t("settings.account.email_not_verified")}</span>`
        }
      </div>

      ${
        !isEmailVerified
          ? me?.email_sending_available
            ? `
              <p class="muted" style="margin-top: 8px;">
                ${t("settings.account.email_verification_hint")}
              </p>

              <button type="button" class="btn" id="request-email-verification-btn">
                ${t("settings.account.send_verification_email")}
              </button>
            `
            : `
              <p class="muted" style="margin-top: 8px;">
                ${t("email.smtp_configure_hint")}
              </p>
            `
          : ""
      }
    </article>
  `;
}


function formatApiKeyScopes(scopes = []) {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return "aucun scope";
  }

  return scopes.join(", ");
}

function renderApiKeysHtml(apiKeys = []) {
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
          : `<p class="muted">Aucune clé API créée.</p>`
      }
    </div>
  `;
}

function renderProwlarrSettingsHtml(integrationSettings = {}, apiKeys = []) {
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

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let value = bytes;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

export function renderEspaceContent(data) {
  const files = Array.isArray(data?.files) ? data.files : [];
  const url = data?.url || "";
  const fileCount = data?.file_count ?? 0;
  const totalSize = data?.total_size_bytes ?? 0;

  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.espace.title")}</h2>
        <p class="muted">${t("settings.espace.subtitle")}</p>
      </div>
    </div>

    <article class="job-card">
      <div style="display:flex;flex-direction:column;gap:8px;">
        <label style="font-size:0.875rem;color:var(--text-muted)">${t("settings.espace.public_url_label")}</label>
        <div style="display:flex;gap:8px;align-items:center;">
          <a class="public-space-url" href="${html(url)}" target="_blank" rel="noopener" title="${html(url)}">${html(url)}</a>
          <button class="btn btn-sm public-space-copy-btn" id="espace-copy-btn" data-url="${html(url)}" type="button" title="${t("settings.espace.copy_link")}" aria-label="${t("settings.espace.copy_link")}">&#x29C9;</button>
        </div>
      </div>

      <div style="display:flex;gap:24px;margin-top:16px;">
        <div>
          <div class="muted" style="font-size:0.75rem;">${t("settings.espace.file_count")}</div>
          <div style="font-weight:600;">${fileCount}</div>
        </div>
        <div>
          <div class="muted" style="font-size:0.75rem;">${t("settings.espace.total_size")}</div>
          <div style="font-weight:600;">${formatBytes(totalSize)}</div>
        </div>
      </div>
    </article>

    <div class="section-header" style="margin-top:8px;">
      <h3 style="font-size:1rem;">${t("settings.espace.files_title")}</h3>
    </div>

    ${
      files.length === 0
        ? `<p class="muted">${t("settings.espace.no_files")}</p>`
        : `<div class="settings-list">${files.map((f) => {
            const encodedPath = f.relative_path.split("/").map(encodeURIComponent).join("/");
            const fileUrl = `${url.replace(/\/$/, "")}/files/${encodedPath}`;
            return `
            <article class="job-card" style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
              <a href="${html(fileUrl)}" target="_blank" rel="noopener" style="word-break:break-all;color:var(--accent);">${html(f.relative_path)}</a>
              <span class="muted" style="white-space:nowrap;font-size:0.8rem;">${formatBytes(f.size_bytes)}</span>
            </article>`;
          }).join("")}</div>`
    }

    <div id="espace-feedback" style="margin-top:8px;" hidden></div>

    <button class="btn" id="espace-cleanup-btn" style="margin-top:8px;color:var(--color-danger,#f87171);">
      ${t("settings.espace.cleanup_btn")}
    </button>
  `;
}

function renderEspacePanel() {
  return `
    <div id="espace-content">
      <p class="muted">${t("settings.espace.loading")}</p>
    </div>
  `;
}

export function renderSettingsPanel(data = {}, me = null) {
  const container = document.getElementById("settings-panel");
  if (!container) return;

  const providers = Array.isArray(data.providers) ? data.providers : [];
  const destinations = Array.isArray(data.destinations) ? data.destinations : [];
  const notificationConfigs = Array.isArray(data.notificationConfigs)
    ? data.notificationConfigs
    : [];

  const notificationRules = Array.isArray(data.notificationRules)
    ? data.notificationRules
    : [];

  const apiKeys = Array.isArray(data.apiKeys) ? data.apiKeys : [];
  const integrationSettings = data.integrationSettings || {};

  const canUseLocalSpace = Boolean(me?.can_use_local_space);

  let activeTab = getActiveSettingsTab();
  if (activeTab === "espace" && !canUseLocalSpace) {
    activeTab = "account";
    setActiveSettingsTab("account");
  }

  const tabBtn = (key) =>
    `<button class="admin-tab${activeTab === key ? " is-active" : ""}" data-settings-tab="${key}">${t(`settings.tabs.${key}`)}</button>`;

  const panel = (key, content) =>
    `<div data-settings-panel="${key}"${activeTab !== key ? " hidden" : ""}>${content}</div>`;

  container.innerHTML = `
    <div class="admin-tabs">
      ${tabBtn("account")}
      ${tabBtn("providers")}
      ${tabBtn("destinations")}
      ${tabBtn("api_keys")}
      ${tabBtn("notifications")}
      ${tabBtn("prowlarr")}
      ${canUseLocalSpace ? tabBtn("espace") : ""}
    </div>

    ${panel("account", `
      <div class="section-header">
        <div>
          <h2>${t("settings.account.title")}</h2>
          <p class="muted">${t("settings.account.subtitle")}</p>
        </div>
      </div>

      <form id="my-profile-form" class="form-grid">
        <label>
          <span>${t("settings.account.email_label")}</span>
          <input name="email" type="email" value="${html(me?.email || "")}" required />
          <p class="muted">${t("settings.account.email_hint")}</p>
        </label>

        <label>
          <span>${t("settings.account.display_name_label")}</span>
          <input name="display_name" value="${html(me?.display_name || "")}" />
        </label>

        <label>
          <span>${t("settings.account.language_label")}</span>
          <select name="preferred_language">
            <option value="en" ${(!me?.preferred_language || me?.preferred_language === "en") ? "selected" : ""}>${t("settings.account.language_en")}</option>
            <option value="fr" ${me?.preferred_language === "fr" ? "selected" : ""}>${t("settings.account.language_fr")}</option>
          </select>
        </label>

        <label>
          <span>${t("settings.account.theme_label")}</span>
          <select name="ui_theme">
            <option value="auto" ${(!me?.ui_theme || me?.ui_theme === "auto") ? "selected" : ""}>${t("settings.account.theme_auto")}</option>
            <option value="light" ${me?.ui_theme === "light" ? "selected" : ""}>${t("settings.account.theme_light")}</option>
            <option value="night" ${me?.ui_theme === "night" ? "selected" : ""}>${t("settings.account.theme_night")}</option>
            <option value="high_contrast" ${me?.ui_theme === "high_contrast" ? "selected" : ""}>${t("settings.account.theme_high_contrast")}</option>
            <option value="colorblind" ${me?.ui_theme === "colorblind" ? "selected" : ""}>${t("settings.account.theme_colorblind")}</option>
          </select>
        </label>

        <label class="checkbox-row">
          <input
            type="checkbox"
            name="receive_application_emails"
            ${Boolean(me?.receive_application_emails) ? "checked" : ""}
          />
          <span>${t("settings.account.receive_application_emails_label")}</span>
        </label>
        <p class="muted">${t("settings.account.receive_application_emails_hint")}</p>
        ${me?.receive_application_emails && !me?.email_verified ? `<p class="muted">${t("settings.account.email_unverified_for_announcements")}</p>` : ""}

        <button class="btn btn-primary">${t("settings.account.save_profile")}</button>
      </form>

      ${renderEmailStatus(me)}

      ${
        me?.single_user_mode
          ? `
            <article class="job-card">
              <strong>${t("settings.account.single_user_title")}</strong>
              <p class="muted">${t("settings.account.single_user_password_disabled")}</p>
              <p class="muted">${t("settings.account.single_user_access_hint")}</p>
            </article>
          `
          : `
            <form id="change-password-form" class="form-grid">
              <label>
                <span>${t("settings.account.current_password_label")}</span>
                <input name="current_password" type="password" required />
              </label>

              <label>
                <span>${t("settings.account.new_password_label")}</span>
                <input name="new_password" type="password" minlength="8" required />
              </label>

              <button class="btn">${t("settings.account.change_password")}</button>
            </form>
          `
      }
    `)}

    ${panel("api_keys", renderApiKeysHtml(apiKeys))}
    ${panel("prowlarr", renderProwlarrSettingsHtml(integrationSettings, apiKeys))}
    ${panel("providers", renderProvidersHtml(providers))}
    ${panel("destinations", renderDestinationsHtml(destinations, canUseLocalSpace))}
    ${panel("notifications", renderNotificationsHtml(notificationConfigs, notificationRules, me?.email_sending_available ?? false))}
    ${canUseLocalSpace ? panel("espace", renderEspacePanel()) : ""}
  `;

  updateDestinationFields();
  updateNotificationChannelFields();

  container.querySelectorAll(".admin-tab[data-settings-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.settingsTab;
      if (!VALID_SETTINGS_TABS.includes(tab)) return;
      setActiveSettingsTab(tab);
      container.querySelectorAll("[data-settings-panel]").forEach((p) => {
        p.hidden = p.dataset.settingsPanel !== tab;
      });
      container.querySelectorAll(".admin-tab[data-settings-tab]").forEach((b) => {
        b.classList.toggle("is-active", b.dataset.settingsTab === tab);
      });
      container.dispatchEvent(new CustomEvent("settings-tab-change", { detail: { tab }, bubbles: true }));
    });
  });

  container.querySelectorAll(".settings-subtab[data-notification-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const subtab = btn.dataset.notificationTab;
      setActiveNotificationSubtab(subtab);
      container.querySelectorAll("[data-notification-panel]").forEach((p) => {
        p.hidden = p.dataset.notificationPanel !== subtab;
      });
      container.querySelectorAll(".settings-subtab[data-notification-tab]").forEach((b) => {
        b.classList.toggle("is-active", b.dataset.notificationTab === subtab);
      });
    });
  });
}

function renderProvidersHtml(providers = []) {
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
          : `<p class="muted">Aucun provider configuré.</p>`
      }
    </div>
  `;
}

function renderDestinationsHtml(destinations = [], canUseLocalSpace = true) {
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
      </labelnas.localbel class="checkbox-row" data-destination-field="synology">
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
          : `<p class="muted">Aucune destination configurée.</p>`
      }
    </div>
  `;
}

function formatNotificationChannel(channel) {
  const value = String(channel || "").trim().toLowerCase();

  if (value === "email") return "Email";
  if (value === "gotify") return "Gotify";
  if (value === "webhook") return "Webhook";

  return value || "—";
}

function formatNotificationSeverity(severity) {
  const value = String(severity || "").trim().toLowerCase();

  if (value === "info") return "Info";
  if (value === "warning") return "Warning";
  if (value === "error") return "Error";
  if (value === "critical") return "Critical";

  return value || "—";
}

function formatNotificationEventTypes(eventTypes = []) {
  if (!Array.isArray(eventTypes) || eventTypes.length === 0) {
    return "Tous les événements";
  }

  return eventTypes.join(", ");
}

function renderNotificationChannelFields() {
  return `
    <div data-notification-channel-field="email">
      <label>
        <span>${t("settings.notifications.email_to")}</span>
        <input name="to_email" type="email" placeholder="${t("settings.notifications.email_to_placeholder")}" />
      </label>
      <p class="muted">
        ${t("settings.notifications.email_to_hint")}
      </p>
    </div>

    <div data-notification-channel-field="gotify">
      <label>
        <span>${t("settings.notifications.gotify_server_url")}</span>
        <input name="gotify_server_url" placeholder="https://gotify.example.com" />
      </label>

      <label>
        <span>${t("settings.notifications.gotify_token")}</span>
        <input name="gotify_token" type="password" placeholder="${t("settings.notifications.gotify_token_placeholder")}" />
      </label>
    </div>

    <div data-notification-channel-field="webhook">
      <label>
        <span>${t("settings.notifications.webhook_url")}</span>
        <input name="webhook_url" placeholder="https://example.com/webhook" />
      </label>

      <label>
        <span>${t("settings.notifications.webhook_method")}</span>
        <select name="webhook_method">
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
        </select>
      </label>

      <label>
        <span>${t("settings.notifications.webhook_headers")}</span>
        <textarea name="webhook_headers" rows="4" placeholder='{"Authorization":"Bearer xxx"}'></textarea>
      </label>
    </div>
  `;
}

function renderNotificationConfigOptions(notificationConfigs = [], selectedId = "") {
  const activeConfigs = notificationConfigs.filter((cfg) => cfg.is_enabled);
  if (!activeConfigs.length) {
    return `<option value="">${t("settings.notifications.no_channel_option")}</option>`;
  }

  return activeConfigs.map((cfg) => `
    <option value="${html(cfg.id)}" ${cfg.id === selectedId ? "selected" : ""}>
      ${html(cfg.name)} — ${html(formatNotificationChannel(cfg.channel))}
    </option>
  `).join("");
}

function formatEventTypeLabel(type) {
  const map = {
    "job.completed":      "settings.notifications.event_job_completed",
    "job.failed":         "settings.notifications.event_job_failed",
    "job.links_ready":    "settings.notifications.event_job_links_ready",
    "job.cancelled":      "settings.notifications.event_job_cancelled",
    "destination.sent":   "settings.notifications.event_destination_sent",
    "destination.failed": "settings.notifications.event_destination_failed",
    "provider.failed":    "settings.notifications.event_provider_failed",
  };
  const key = map[String(type || "").trim().toLowerCase()];
  return key ? t(key) : String(type);
}

function renderNotificationChannelDetails(cfg) {
  const config = cfg.config || {};
  const channel = String(cfg.channel || "").trim().toLowerCase();
  const row = (labelKey, value) => {
    const safeValue = html(String(value ?? "—"));
    return `<div>
      <span class="notification-channel-detail-label">${t(labelKey)}</span>
      <span class="notification-channel-detail-value" title="${safeValue}">${safeValue}</span>
    </div>`;
  };

  if (channel === "email") {
    return row("settings.notifications.detail_to_email", config.to_email || "—");
  }
  if (channel === "gotify") {
    return row("settings.notifications.detail_server_url", config.server_url || "—");
  }
  if (channel === "webhook") {
    return [
      row("settings.notifications.detail_url", config.url || "—"),
      row("settings.notifications.detail_method", config.method || "POST"),
    ].join("");
  }
  return "";
}

function renderNotificationsHtml(notificationConfigs = [], notificationRules = [], emailAvailable = true) {
  const activeSubtab = getActiveNotificationSubtab();
  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.notifications.title")}</h2>
        <p class="muted">${t("settings.notifications.subtitle")}</p>
      </div>
    </div>

    <div id="notification-feedback" hidden></div>

    <div class="settings-subtabs">
      <button class="settings-subtab${activeSubtab === "channels" ? " is-active" : ""}" data-notification-tab="channels">
        ${t("settings.notifications.tab_channels")}
      </button>
      <button class="settings-subtab${activeSubtab === "rules" ? " is-active" : ""}" data-notification-tab="rules">
        ${t("settings.notifications.tab_rules")}
      </button>
    </div>

    <div data-notification-panel="channels"${activeSubtab !== "channels" ? " hidden" : ""}>
    <section class="detail-block">
      <h3>${t("settings.notifications.channels_title")}</h3>

      <form id="notification-channel-form" class="form-grid">
        <input type="hidden" name="config_id" />

        <label>
          <span>${t("settings.notifications.channel_name")}</span>
          <input name="name" placeholder="${t("settings.notifications.channel_name_placeholder")}" required />
        </label>

        <label>
          <span>${t("settings.notifications.channel_type")}</span>
          <select name="channel" id="notification-channel" required>
            <option value="email" ${!emailAvailable ? "disabled" : ""}>${emailAvailable ? "Email" : `Email (${t("email.sending_not_configured")})`}</option>
            <option value="gotify">Gotify</option>
            <option value="webhook">Webhook</option>
          </select>
        </label>

        ${renderNotificationChannelFields()}

        <div class="notification-channel-form-footer">
          <div class="notification-channel-form-flags">
            <label class="checkbox-row">
              <input type="checkbox" name="is_enabled" checked />
              <span>${t("settings.notifications.channel_enabled")}</span>
            </label>
            <label class="checkbox-row">
              <input type="checkbox" name="is_default" />
              <span>${t("settings.notifications.channel_default")}</span>
            </label>
          </div>
          <div class="form-actions notification-channel-form-actions">
            <button type="submit" class="btn btn-primary">${t("settings.notifications.save_channel")}</button>
            <button type="button" class="btn" data-settings-action="test-notification-channel-form">
              ${t("settings.notifications.test_channel")}
            </button>
            <button type="button" class="btn" data-settings-action="reset-notification-channel-form">
              ${t("common.reset")}
            </button>
            <button type="button" class="btn" data-settings-action="cancel-notification-channel-edit" hidden>
              ${t("common.cancel")}
            </button>
          </div>
        </div>
      </form>

      <div class="settings-subsection-header">
        <h3>${t("settings.notifications.configured_channels_title")}</h3>
      </div>

      <div class="settings-list notification-channel-list">
        ${
          notificationConfigs.length
            ? notificationConfigs.map((cfg) => `
                <article class="job-card notification-channel-card">
                  <div class="notification-channel-main">
                    <div class="notification-channel-title-row">
                      <strong>${html(cfg.name)}</strong>
                      ${cfg.is_enabled
                        ? `<span class="meta-pill is-success">${t("settings.notifications.badge_enabled")}</span>`
                        : `<span class="meta-pill is-muted">${t("settings.notifications.badge_disabled")}</span>`
                      }
                      ${cfg.is_default ? `<span class="meta-pill">${t("settings.notifications.badge_default")}</span>` : ""}
                    </div>

                    <div class="notification-channel-meta">
                      <span class="meta-pill">${html(formatNotificationChannel(cfg.channel))}</span>
                    </div>

                    <div class="notification-channel-details">
                      ${renderNotificationChannelDetails(cfg)}
                    </div>
                  </div>

                  <div class="notification-channel-actions inline-actions">
                    <div class="notification-channel-toggles">
                      <label class="notification-channel-toggle">
                        <input
                          type="checkbox"
                          data-settings-action="toggle-notification-channel-enabled"
                          data-notification-config-id="${html(cfg.id)}"
                          ${cfg.is_enabled ? "checked" : ""}
                        />
                        <span>${t("settings.notifications.badge_enabled")}</span>
                      </label>
                      <label class="notification-channel-toggle">
                        <input
                          type="checkbox"
                          data-settings-action="set-notification-channel-default"
                          data-notification-config-id="${html(cfg.id)}"
                          ${cfg.is_default ? "checked" : ""}
                        />
                        <span>${t("settings.notifications.badge_default")}</span>
                      </label>
                    </div>
                    <button type="button" class="btn" data-settings-action="edit-notification-channel" data-notification-config-id="${html(cfg.id)}">
                      ${t("common.edit")}
                    </button>
                    <button type="button" class="btn" data-settings-action="test-stored-notification-channel" data-notification-config-id="${html(cfg.id)}">
                      ${t("common.test")}
                    </button>
                    <button type="button" class="btn btn-danger" data-settings-action="delete-notification-channel" data-notification-config-id="${html(cfg.id)}">
                      ${t("common.delete")}
                    </button>
                  </div>
                </article>
              `).join("")
            : `<p class="muted">${t("settings.notifications.empty_channels")}</p>`
        }
      </div>
    </section>
    </div>

    <div data-notification-panel="rules"${activeSubtab !== "rules" ? " hidden" : ""}>
    <section class="detail-block">
      <h3>${t("settings.notifications.rules_title")}</h3>

      ${
        notificationConfigs.length === 0
          ? `<p class="muted">${t("settings.notifications.rules_no_channel")}</p>`
          : notificationConfigs.every((cfg) => !cfg.is_enabled)
            ? `<p class="muted">${t("settings.notifications.rules_no_active_channel")}</p>`
            : `
      <form id="notification-rule-form" class="form-grid">
        <input type="hidden" name="rule_id" />

        <label>
          <span>${t("settings.notifications.rule_name")}</span>
          <input name="name" placeholder="${t("settings.notifications.rule_name_placeholder")}" required />
        </label>

        <label>
          <span>${t("settings.notifications.rule_channel")}</span>
          <select name="config_id" required>
            ${renderNotificationConfigOptions(notificationConfigs)}
          </select>
        </label>

        <label>
          <span>${t("settings.notifications.rule_severity")}</span>
          <select name="severity_min">
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
            <option value="critical">Critical</option>
          </select>
        </label>

        <fieldset class="detail-block">
          <legend>${t("settings.notifications.rule_event_types")}</legend>

          <div class="notification-event-grid">
            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="job.completed" />
              <span>${t("settings.notifications.event_job_completed")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="job.failed" checked />
              <span>${t("settings.notifications.event_job_failed")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="job.links_ready" />
              <span>${t("settings.notifications.event_job_links_ready")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="job.cancelled" />
              <span>${t("settings.notifications.event_job_cancelled")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="destination.sent" />
              <span>${t("settings.notifications.event_destination_sent")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="destination.failed" checked />
              <span>${t("settings.notifications.event_destination_failed")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="provider.failed" checked />
              <span>${t("settings.notifications.event_provider_failed")}</span>
            </label>
          </div>

          <p class="muted">
            ${t("settings.notifications.event_types_hint")}
          </p>
        </fieldset>

        <label>
          <span>${t("settings.notifications.rule_rate_limit")}</span>
          <input name="rate_limit_per_hour" type="number" min="0" max="1000" value="30" required />
        </label>

        <div class="notification-rule-form-footer">
          <div class="notification-rule-form-flags">
            <label class="checkbox-row">
              <input type="checkbox" name="is_enabled" checked />
              <span>${t("settings.notifications.rule_enabled")}</span>
            </label>
          </div>
          <div class="form-actions notification-rule-form-actions">
            <button type="submit" class="btn btn-primary">${t("settings.notifications.save_rule")}</button>
            <button type="button" class="btn" data-settings-action="reset-notification-rule-form">
              ${t("common.reset")}
            </button>
            <button type="button" class="btn" data-settings-action="cancel-notification-rule-edit" hidden>
              ${t("common.cancel")}
            </button>
          </div>
        </div>
      </form>

      <div class="settings-subsection-header">
        <h3>${t("settings.notifications.configured_rules_title")}</h3>
      </div>

      <div class="settings-list notification-rule-list">
        ${
          notificationRules.length
            ? notificationRules.map((rule) => {
                const cfg = notificationConfigs.find((item) => item.id === rule.config_id);
                const cfgLabel = cfg
                  ? `${cfg.name} — ${formatNotificationChannel(cfg.channel)}`
                  : t("settings.notifications.channel_not_found");
                const cfgDisabled = cfg && !cfg.is_enabled;

                return `
                  <article class="job-card notification-rule-card">
                    <div class="notification-rule-main">
                      <div class="notification-rule-title-row">
                        <strong>${html(rule.name)}</strong>
                        ${rule.is_enabled
                          ? `<span class="meta-pill is-success">${t("settings.notifications.badge_enabled")}</span>`
                          : `<span class="meta-pill is-muted">${t("settings.notifications.badge_disabled")}</span>`
                        }
                      </div>

                      <div class="notification-rule-meta">
                        <span class="meta-pill${cfgDisabled ? " is-muted" : ""}">
                          ${t("settings.notifications.meta_channel")}: ${html(cfgLabel)}${cfgDisabled ? ` (${t("settings.notifications.badge_disabled")})` : ""}
                        </span>
                        <span class="meta-pill">${t("settings.notifications.meta_severity")}: ${html(formatNotificationSeverity(rule.severity_min))}</span>
                        <span class="meta-pill">${t("settings.notifications.meta_rate_limit")}: ${html(String(rule.rate_limit_per_hour))}/h</span>
                        <span class="meta-pill">${t("settings.notifications.meta_scope")}: ${html(rule.scope || "user")}</span>
                      </div>

                      <div class="notification-rule-events">
                        ${Array.isArray(rule.event_types) && rule.event_types.length
                          ? rule.event_types.map((type) => `<span class="meta-pill">${html(formatEventTypeLabel(type))}</span>`).join("")
                          : `<span class="meta-pill is-muted">${t("settings.notifications.meta_all_events")}</span>`
                        }
                      </div>
                    </div>

                    <div class="notification-rule-actions inline-actions">
                      <div class="notification-rule-toggles">
                        <label class="notification-rule-toggle">
                          <input
                            type="checkbox"
                            data-settings-action="toggle-notification-rule-enabled"
                            data-notification-rule-id="${html(rule.id)}"
                            ${rule.is_enabled ? "checked" : ""}
                          />
                          <span>${t("settings.notifications.badge_enabled")}</span>
                        </label>
                      </div>
                      <button type="button" class="btn" data-settings-action="edit-notification-rule" data-notification-rule-id="${html(rule.id)}">
                        ${t("common.edit")}
                      </button>
                      <button type="button" class="btn btn-danger" data-settings-action="delete-notification-rule" data-notification-rule-id="${html(rule.id)}">
                        ${t("common.delete")}
                      </button>
                    </div>
                  </article>
                `;
              }).join("")
            : `<p class="muted">${t("settings.notifications.empty_rules")}</p>`
        }
      </div>
      `}
    </section>
    </div>
  `;
}

/* Compat ancien app.js */
export function renderProvidersPanel(providers = []) {
  const container = document.getElementById("providers-panel");
  if (!container) return;
  container.innerHTML = renderProvidersHtml(providers);
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

export function updateNotificationChannelFields() {
  const select = document.getElementById("notification-channel");
  const channel = select?.value || "email";

  document.querySelectorAll("[data-notification-channel-field]").forEach((field) => {
    field.hidden = field.dataset.notificationChannelField !== channel;
  });
}

export function resetNotificationChannelForm() {
  const form = document.getElementById("notification-channel-form");
  if (!form) return;

  form.reset();
  form.config_id.value = "";
  form.channel.value = "email";
  form.is_enabled.checked = true;
  form.is_default.checked = false;

  if (form.gotify_token) {
    form.gotify_token.placeholder = "Token Gotify";
  }

  if (form.webhook_headers) {
    form.webhook_headers.placeholder = '{"Authorization":"Bearer xxx"}';
  }

  const submit = form.querySelector("button[type='submit']");
  if (submit) submit.textContent = t("settings.notifications.save_channel");

  updateNotificationChannelFields();
}

export function fillNotificationChannelForm(config) {
  const form = document.getElementById("notification-channel-form");
  if (!form || !config) return;

  form.config_id.value = config.id || "";
  form.name.value = config.name || "";
  form.channel.value = config.channel || "email";
  form.is_enabled.checked = Boolean(config.is_enabled);
  form.is_default.checked = Boolean(config.is_default);

  const cfg = config.config || {};

  if (form.to_email) {
    form.to_email.value = cfg.to_email || "";
  }

  if (form.gotify_server_url) {
    form.gotify_server_url.value = cfg.server_url || "";
  }

  if (form.gotify_token) {
    form.gotify_token.value = "";
    form.gotify_token.placeholder = cfg.has_token
      ? t("settings.notifications.gotify_token_saved_hint")
      : t("settings.notifications.gotify_token_placeholder");
  }

  if (form.webhook_url) {
    form.webhook_url.value = cfg.url || "";
  }

  if (form.webhook_method) {
    form.webhook_method.value = cfg.method || "POST";
  }

  if (form.webhook_headers) {
    form.webhook_headers.value = "";
    form.webhook_headers.placeholder = cfg.has_headers
      ? t("settings.notifications.webhook_headers_saved_hint")
      : '{"Authorization":"Bearer xxx"}';
  }

  const submit = form.querySelector("button[type='submit']");
  if (submit) submit.textContent = t("settings.notifications.update_channel");

  const cancelBtn = form.querySelector("[data-settings-action='cancel-notification-channel-edit']");
  if (cancelBtn) cancelBtn.hidden = false;

  updateNotificationChannelFields();
}

export function resetNotificationRuleForm() {
  const form = document.getElementById("notification-rule-form");
  if (!form) return;

  form.reset();
  form.rule_id.value = "";
  form.is_enabled.checked = true;
  form.severity_min.value = "error";
  form.rate_limit_per_hour.value = "30";

  form.querySelectorAll("input[name='event_type']").forEach((input) => {
    input.checked = ["job.failed", "destination.failed", "provider.failed"].includes(input.value);
  });

  const submit = form.querySelector("button[type='submit']");
  if (submit) submit.textContent = t("settings.notifications.save_rule");
}

export function fillNotificationRuleForm(rule) {
  const form = document.getElementById("notification-rule-form");
  if (!form || !rule) return;

  form.rule_id.value = rule.id || "";
  form.name.value = rule.name || "";
  form.config_id.value = rule.config_id || "";
  form.is_enabled.checked = Boolean(rule.is_enabled);
  form.severity_min.value = rule.severity_min || "error";
  form.rate_limit_per_hour.value = rule.rate_limit_per_hour ?? 30;

  const eventTypes = Array.isArray(rule.event_types) ? rule.event_types : [];

  form.querySelectorAll("input[name='event_type']").forEach((input) => {
    input.checked = eventTypes.includes(input.value);
  });

  const submit = form.querySelector("button[type='submit']");
  if (submit) submit.textContent = t("settings.notifications.update_rule");

  const cancelBtn = form.querySelector("[data-settings-action='cancel-notification-rule-edit']");
  if (cancelBtn) cancelBtn.hidden = false;
}

/* Compat temporaire avec vieux app.js si import oublié */
export const updateNotificationFields = updateNotificationChannelFields;
export const resetNotificationForm = resetNotificationChannelForm;
export const fillNotificationConfigForm = fillNotificationChannelForm;