import { t } from "../i18n/index.js";
import { state } from "../state.js";

function html(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function normalizeUrl(url) {
  return String(url || "").trim();
}

function getSettings() {
  return state.integrationSettings || {
    prowlarr_enabled: false,
    prowlarr_url: "",
    prowlarr_open_mode: "both",
    home_page: "jobs",
  };
}

export function hasConfiguredProwlarr() {
  const settings = getSettings();
  return Boolean(settings.prowlarr_enabled && normalizeUrl(settings.prowlarr_url));
}

export function renderProwlarrPanel() {
  const panel = document.getElementById("prowlarr-panel");
  if (!panel) return;

  const settings = getSettings();
  const prowlarrUrl = normalizeUrl(settings.prowlarr_url);
  const mode = settings.prowlarr_open_mode || "both";

  if (!settings.prowlarr_enabled) {
    panel.innerHTML = `
      <div class="section-header">
        <div>
          <h2>Prowlarr</h2>
          <p class="muted">${t("prowlarr.disabled_subtitle")}</p>
        </div>
      </div>

      <div class="empty-state">
        <strong>${t("prowlarr.disabled_title")}</strong>
        <p class="muted">${t("prowlarr.disabled_hint")}</p>
        <button type="button" class="btn btn-primary" data-action="go-settings">
          ${t("prowlarr.open_settings")}
        </button>
      </div>
    `;
    return;
  }

  if (!prowlarrUrl) {
    panel.innerHTML = `
      <div class="section-header">
        <div>
          <h2>Prowlarr</h2>
          <p class="muted">${t("prowlarr.no_url_subtitle")}</p>
        </div>
      </div>

      <div class="empty-state">
        <strong>${t("prowlarr.no_url_title")}</strong>
        <p class="muted">${t("prowlarr.no_url_hint")}</p>
        <button type="button" class="btn btn-primary" data-action="go-settings">
          ${t("prowlarr.open_settings")}
        </button>
      </div>
    `;
    return;
  }

  const showIframe = mode === "iframe" || mode === "both";

  panel.innerHTML = `
    <div class="section-header">
      <div>
        <h2>Prowlarr</h2>
        <p class="muted">${t("prowlarr.description")}</p>
      </div>

      ${showIframe ? `
      <a class="btn" href="${html(prowlarrUrl)}" target="_blank" rel="noopener noreferrer">
        ${t("prowlarr.open_new_tab")}
      </a>` : ""}
    </div>

    ${
      showIframe
        ? `
          <div class="prowlarr-frame-wrap">
            <iframe
              class="prowlarr-frame"
              src="${html(prowlarrUrl)}"
              title="Prowlarr"
              loading="lazy"
            ></iframe>
          </div>

          <p class="muted prowlarr-frame-help">
            ${t("prowlarr.iframe_hint")}
          </p>
        `
        : `
          <div class="empty-state">
            <strong>${t("prowlarr.external_title")}</strong>
            <p class="muted">${t("prowlarr.external_hint")}</p>
            <a class="btn btn-primary" href="${html(prowlarrUrl)}" target="_blank" rel="noopener noreferrer">
              ${t("prowlarr.open_prowlarr")}
            </a>
          </div>
        `
    }
  `;
}
