import { escapeHtml, statusBadgeClass, formatJobStatus } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { renderJobActions } from "./actions.js";
import { renderJobMessage } from "./status.js";
import { getJobPanelState } from "./panel-state.js";
import { renderDestinationBlock } from "./destination.js";
import { renderFilesBlock } from "./files.js";
import { formatProviderProfile, formatDestinationProfile, renderSummaryBlock } from "./summary.js";
import { renderTechnicalBlock } from "./technical.js";

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
