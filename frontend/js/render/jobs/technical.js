import { escapeHtml } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { isPanelOpen } from "./panel-state.js";

export function renderTechnicalBlock(job) {
  const technicalOpen = isPanelOpen(job, "technical", false);

  return `
    <details class="detail-block collapsible-block" data-panel="technical" ${technicalOpen ? "open" : ""}>
      <summary>${t("job.technical")}</summary>
      <div class="collapsible-content">
        <div class="kv-grid">
          <div class="kv-item"><strong>ID</strong><div class="code-block">${escapeHtml(job.id)}</div></div>
          <div class="kv-item"><strong>${t("job.output_mode")}</strong><div>${escapeHtml(job.output_mode || t("common.none"))}</div></div>
          <div class="kv-item"><strong>${t("job.torrent_id")}</strong><div class="code-block">${escapeHtml(job.torrent_id || t("common.none"))}</div></div>
          <div class="kv-item"><strong>${t("job.torrent_status")}</strong><div>${escapeHtml(job.torrent_status || t("common.none"))}</div></div>
          <div class="kv-item"><strong>${t("job.selected_files")}</strong><div>${escapeHtml(job.selected_files || t("common.none"))}</div></div>
          <div class="kv-item"><strong>${t("job.error")}</strong><div>${escapeHtml(job.error_message || t("common.none"))}</div></div>
        </div>
      </div>
    </details>
  `;
}
