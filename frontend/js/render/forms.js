import { t } from "../i18n/index.js";
import { state } from "../state.js";

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

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

function formatDestinationType(destinationType) {
  const value = String(destinationType || "").trim().toLowerCase();

  if (value === "synology" || value === "nas") return "NAS Synology";
  if (value === "local") return "Local";

  return destinationType || "-";
}

function formatDestinationProfile(destination) {
  const name = String(destination?.name || destination?.destination_profile_name || "").trim();
  const type = formatDestinationType(destination?.destination_type || destination?.destination_name);

  return name ? `${name} (${type})` : type;
}

function isTruthy(value) {
  return value === true || value === 1 || value === "1" || value === "true" || value === "t";
}

function getEnabledProviders() {
  return (state.providers || []).filter((provider) => isTruthy(provider.is_enabled));
}

function getDefaultProviderId(providers) {
  const defaultProvider = providers.find((provider) => provider.is_default);
  return defaultProvider?.id || providers[0]?.id || "";
}

function getRealDestinations() {
  const canUseLocalSpace = Boolean(state.currentUser?.can_use_local_space);
  return (state.destinations || []).filter((destination) => {
    const type = destination.destination_type || destination.destination_name;
    if (!canUseLocalSpace && type === "local") return false;
    return isTruthy(destination.is_enabled) && ["synology", "nas", "local"].includes(type);
  });
}

function getDefaultDestinationId(destinations) {
  const defaultDestination = destinations.find((destination) => destination.is_default);
  return defaultDestination?.id || destinations[0]?.id || "";
}

function renderProviderSelect(providers) {
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
            ${provider.is_default ? " — défaut" : ""}
          </option>
        `).join("")}
      </select>
    </label>
  `;
}

function renderDestinationSelect(destinations) {
  const defaultDestinationId = getDefaultDestinationId(destinations);
  const defaultDestination = destinations.find((destination) => destination.id === defaultDestinationId) || destinations[0];

  return `
    <div id="create-destination-select-wrap" hidden>
      ${
        destinations.length === 1
          ? `
            <input type="hidden" name="destination_config_id" value="${escapeHtml(defaultDestinationId)}" />
            <div class="readonly-selection">
              <span class="muted">Destination</span>
              <strong>${escapeHtml(formatDestinationProfile(defaultDestination))}</strong>
            </div>
          `
          : destinations.length > 1
            ? `
              <label>
                <span>Destination</span>
                <select name="destination_config_id">
                  ${destinations.map((destination) => `
                    <option
                      value="${escapeHtml(destination.id)}"
                      ${destination.id === defaultDestinationId ? "selected" : ""}
                    >
                      ${escapeHtml(formatDestinationProfile(destination))}
                      ${destination.is_default ? " — défaut" : ""}
                    </option>
                  `).join("")}
                </select>
              </label>
            `
            : `
              <div class="empty-state">
                <strong>${t("form.no_destination")}</strong>
                <p class="muted">${t("form.no_destination_hint")}</p>
              </div>
            `
      }
    </div>
  `;
}

export function updateCreateJobDestinationVisibility() {
  const form = document.getElementById("create-job-form");
  if (!form) return;

  const checkbox = form.send_to_destination;
  const wrap = document.getElementById("create-destination-select-wrap");

  if (!wrap || !checkbox) return;

  wrap.hidden = !checkbox.checked;
}

export function renderCreateJobForm() {
  const container = document.getElementById("create-job-panel");

  if (!container) return;

  const providers = getEnabledProviders();
  const realDestinations = getRealDestinations();
  const canCreate = providers.length > 0;


if (!canCreate) {
  document.querySelector(".content-grid")?.setAttribute("hidden", "hidden");

  container.innerHTML = `
    <div class="section-header">
      <h2>${t("form.create_jobs")}</h2>
    </div>

    <div class="empty-state">
      <strong>${t("form.no_provider")}</strong>
      <p class="muted">${t("form.no_provider_hint")}</p>
    </div>
  `;
  return;
}

document.querySelector(".content-grid")?.removeAttribute("hidden");

container.innerHTML = `
    <details class="create-job-details" open>
      <summary class="create-job-summary">${t("form.create_jobs")}</summary>

      <form id="create-job-form" class="form-grid">
      ${renderProviderSelect(providers)}

      <p class="form-section-label">${t("form.section_source")}</p>

      <label>
        <span>${t("form.links_magnets")}</span>
        <textarea
          name="source_value"
          rows="6"
          placeholder="${t("form.placeholder_sources")}"
          ${!canCreate ? "disabled" : ""}
        ></textarea>
      </label>

      <div class="muted">${t("form.magnet_help")}</div>

      <label class="torrent-dropzone">
        <span class="torrent-dropzone-text">${t("form.torrent_drop_label")}</span>
        <input
          type="file"
          name="torrent_file"
          accept=".torrent"
          multiple
          ${!canCreate ? "disabled" : ""}
        />
        <p class="muted">${t("form.torrent_hint")}</p>
      </label>

      <p class="form-section-label">${t("form.section_options")}</p>

      <label class="checkbox-row">
        <input
          type="checkbox"
          name="auto_start"
          checked
          ${!canCreate ? "disabled" : ""}
        />
        <span>${t("form.auto_start")}</span>
      </label>

      ${
        realDestinations.length
          ? `
            <label class="checkbox-row">
              <input
                type="checkbox"
                name="send_to_destination"
                ${!canCreate ? "disabled" : ""}
              />
              <span>${
                realDestinations.length === 1
                  ? t("form.send_to_named_destination", { destination: escapeHtml(formatDestinationProfile(realDestinations[0])) })
                  : t("form.send_to_destination")
              }</span>
            </label>

            ${renderDestinationSelect(realDestinations)}
          `
          : ``
      }

      <button
        type="submit"
        class="btn btn-primary"
        ${!canCreate ? "disabled" : ""}
      >
        ${t("form.create")}
      </button>
    </form>
    </details>
    <div id="create-job-result-panel"></div>
  `;




  bindTorrentDropzone(container);
  updateCreateJobDestinationVisibility();
}

function bindTorrentDropzone(container) {
  const zone = container.querySelector(".torrent-dropzone");
  const input = zone?.querySelector('input[name="torrent_file"]');
  if (!zone || !input) return;

  input.addEventListener("click", (e) => e.stopPropagation());

  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("is-dragover");
  });

  zone.addEventListener("dragleave", (e) => {
    if (zone.contains(e.relatedTarget)) return;
    zone.classList.remove("is-dragover");
  });

  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("is-dragover");

    const torrentFiles = Array.from(e.dataTransfer.files).filter((f) =>
      f.name.toLowerCase().endsWith(".torrent")
    );
    if (torrentFiles.length === 0) return;
    if (typeof DataTransfer === "undefined") return;

    const dt = new DataTransfer();
    for (const file of torrentFiles) dt.items.add(file);
    input.files = dt.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
}
