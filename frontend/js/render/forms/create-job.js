import { t } from "../../i18n/index.js";
import { escapeHtml } from "./utils.js";
import { getEnabledProviders, renderProviderSelect } from "./provider-select.js";
import { getRealDestinations, renderDestinationSelect, formatDestinationProfile } from "./destination-select.js";

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
