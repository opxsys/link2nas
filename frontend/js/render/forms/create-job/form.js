import { t } from "../../../i18n/index.js";
import { escapeHtml } from "../utils.js";
import { renderProviderSelect } from "../provider-select.js";
import { renderDestinationSelect, formatDestinationProfile } from "../destination-select.js";

export function renderCreateJobMainForm(container, { providers, realDestinations, canCreate }) {
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
}
