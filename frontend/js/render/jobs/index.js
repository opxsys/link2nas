import { escapeHtml, formatBytes, formatDate, statusBadgeClass, formatJobStatus } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { renderJobActions } from "./actions.js";
import { renderJobMessage } from "./status.js";
import { getJobPanelState, isPanelOpen } from "./panel-state.js";
import { renderDestinationBlock } from "./destination.js";
import { renderFilesBlock } from "./files.js";

function getDisplaySourceType(job) {
  if (job.source_type === "magnet" || job.source_type === "torrent_file") return t("jobs.torrent");
  if (job.source_type === "direct_link") return t("jobs.direct");
  return job.source_type || t("common.none");
}

function formatProviderType(providerType) {
  const value = String(providerType || "").trim().toLowerCase();
  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";
  return t("common.none");
}

function formatProviderProfile(job) {
  const name = String(job.provider_profile_name || "").trim();
  const type = formatProviderType(job.provider_type || job.provider_name);
  return name ? `${name} (${type})` : type;
}

function formatDestinationType(destinationType) {
  const value = String(destinationType || "").trim().toLowerCase();
  if (value === "synology" || value === "nas") return "NAS Synology";
  if (value === "local") return "Local";
  return t("common.none");
}

function formatDestinationProfile(job) {
  const name = String(job.destination_profile_name || "").trim();
  const type = formatDestinationType(job.destination_type || job.destination_name);
  return name ? `${name} (${type})` : type;
}

function renderSummaryBlock(job, progress) {
  return `
    <div class="detail-block detail-block-first">
      <h3>${t("job.summary")}</h3>
      <div class="kv-grid">
        <div class="kv-item"><strong>${t("job.source")}</strong><div>${escapeHtml(getDisplaySourceType(job))}</div></div>
        <div class="kv-item"><strong>${t("common.status")}</strong><div>${escapeHtml(formatJobStatus(job.status))}</div></div>
        <div class="kv-item"><strong>Provider</strong><div>${escapeHtml(formatProviderProfile(job))}</div></div>
        <div class="kv-item"><strong>Destination</strong><div>${escapeHtml(formatDestinationProfile(job))}</div></div>
        <div class="kv-item kv-item-wide">
          <strong>${t("job.progress")}</strong>
          <div>${escapeHtml(String(progress))}%</div>
          <div class="progress summary-progress"><span style="width:${Number(progress)}%"></span></div>
        </div>
        <div class="kv-item"><strong>${t("job.size")}</strong><div>${escapeHtml(formatBytes(job.filesize))}</div></div>
        <div class="kv-item"><strong>${t("job.created_at")}</strong><div>${escapeHtml(formatDate(job.created_at))}</div></div>
        <div class="kv-item"><strong>${t("job.updated_at")}</strong><div>${escapeHtml(formatDate(job.updated_at))}</div></div>
      </div>
    </div>
  `;
}

function renderTechnicalBlock(job) {
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

function bindDetailsState(job) {
  const container = document.getElementById("job-details");
  if (!container || !job?.id) return;

  const panelState = getJobPanelState(job.id);

  container.querySelectorAll("details[data-panel]").forEach((detailsEl) => {
    const panelName = detailsEl.dataset.panel;
    if (!panelName) return;

    detailsEl.addEventListener("toggle", () => {
      panelState[panelName] = detailsEl.open;
    });
  });
}

export function forceOpenJobPanel(jobId, panelName) {
  const panelState = getJobPanelState(jobId);
  panelState[panelName] = true;
}

export function renderJobDetails(job) {
  const container = document.getElementById("job-details");
  if (!container) return;

  if (!job) {
    container.innerHTML = `<p class="muted">${t("common.no_job_selected")}</p>`;
    return;
  }

  const progress = job.progress ?? 0;
  const perFileHint = job.output_mode === "per_file"
    ? `<p class="muted">${t("job.per_file_hint")}</p>`
    : "";

  container.innerHTML = `
    <div class="section-header">
      <div class="detail-title-wrap">
        <strong class="detail-title">${escapeHtml(job.filename || job.id)}</strong>
      </div>
      <span class="${statusBadgeClass(job.status)}">${escapeHtml(formatJobStatus(job.status))}</span>
    </div>

    <div class="job-context-strip">
      <span>Provider : ${escapeHtml(formatProviderProfile(job))}</span>
      <span class="job-context-sep">•</span>
      <span>Destination : ${escapeHtml(formatDestinationProfile(job))}</span>
    </div>

    ${renderJobActions(job)}
    ${renderJobMessage(job)}

    ${renderSummaryBlock(job, progress)}

    ${perFileHint ? `<div class="detail-block">${perFileHint}</div>` : ""}

    ${renderDestinationBlock(job)}
    ${renderTechnicalBlock(job)}
    ${renderFilesBlock(job)}
  `;

  bindDetailsState(job);
}
