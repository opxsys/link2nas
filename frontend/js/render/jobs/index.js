import { escapeHtml, formatBytes, formatDate, statusBadgeClass, formatJobStatus } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { state } from "../../state.js";
import { renderJobActions, renderAsyncButton } from "./actions.js";
import { resolveTranslatedMessage, formatDestinationStatus, renderJobMessage } from "./status.js";

function getJobPanelState(jobId) {
  const key = String(jobId || "").trim();
  if (!key) return {};

  if (!state.detailPanelsByJobId[key]) {
    state.detailPanelsByJobId[key] = {};
  }

  return state.detailPanelsByJobId[key];
}

function isPanelOpen(job, panelName, defaultValue = false) {
  const panelState = getJobPanelState(job?.id);
  const value = panelState[panelName];

  return typeof value === "boolean" ? value : defaultValue;
}

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

function renderDestinationBlock(job) {
  const resolvedDestinationMessage = resolveTranslatedMessage(
    job.destination_message_key,
    job.destination_message_params,
    job.destination_message
  );

  const destinationStatus = String(job.destination_status || "").trim().toLowerCase();


  const destinationName = String(job.destination_name || job.destination_type || "")
    .trim()
    .toLowerCase();

  const isLocalDestination = destinationName === "local";

  const destinationProgress = Math.max(
    0,
    Math.min(100, Number(job.destination_progress || 0))
  );

  const showDestinationProgress =
    isLocalDestination &&
    (
      destinationStatus === "downloading" ||
      destinationStatus === "queued" ||
      destinationStatus === "sent"
    );

  const destinationMessageClass =
    destinationStatus === "failed" ? "destination-message is-error" : "destination-message";

  const defaultOpen =
    Boolean(job.send_to_destination) ||
    Boolean(job.sent_to_destination) ||
    Boolean(job.destination_status) ||
    Boolean(resolvedDestinationMessage) ||
    Boolean(job.destination_path);

  const destinationOpen = isPanelOpen(job, "destination", defaultOpen);

  return `
    <details class="detail-block collapsible-block" data-panel="destination" ${destinationOpen ? "open" : ""}>
      <summary>${t("destination.title")}</summary>
      <div class="collapsible-content">
        <div class="kv-grid">
          <div class="kv-item"><strong>${t("destination.send")}</strong><div>${job.send_to_destination ? t("destination.yes") : t("destination.no")}</div></div>
          <div class="kv-item"><strong>${t("destination.sent")}</strong><div>${job.sent_to_destination ? t("destination.yes") : t("destination.no")}</div></div>
          <div class="kv-item"><strong>${t("destination.status")}</strong><div>${escapeHtml(formatDestinationStatus(job))}</div></div>
              ${
            showDestinationProgress
              ? `<div class="kv-item"><strong>${t("job.local_progress")}</strong><div>${escapeHtml(String(destinationProgress))}%</div></div>`
              : ``
          }
          <div class="kv-item"><strong>${t("destination.message")}</strong><div class="${destinationMessageClass}">${escapeHtml(resolvedDestinationMessage || t("common.none"))}</div></div>
          <div class="kv-item"><strong>${t("destination.path")}</strong><div class="code-block">${escapeHtml(job.destination_path || t("common.none"))}</div></div>
          <div class="kv-item"><strong>${t("destination.last_attempt")}</strong><div>${escapeHtml(formatDate(job.destination_last_attempt))}</div></div>
          <div class="kv-item"><strong>${t("destination.sent_at")}</strong><div>${escapeHtml(formatDate(job.sent_to_destination_at))}</div></div>
        </div>
        ${
          showDestinationProgress
            ? `
              <div class="progress-bar-top progress">
                <span style="width:${destinationProgress}%"></span>
              </div>
            `
            : ``
        }
      </div>
    </details>
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

function renderFiles(files, job) {
  if (!files?.length) {
    return `<p class="muted">${t("common.no_file")}</p>`;
  }

  return files.map((file) => {
    const copyFileLabel = file._copyDone ? t("common.copied") : t("common.copy");

    return `
      <div class="file-row">
        <div class="file-main">
          <div class="file-path">
            <strong>${escapeHtml(file.path || file.filename || t("job.file_fallback", { id: file.id }))}</strong>
          </div>
          <div class="muted">
            id=${escapeHtml(file.id)} • ${escapeHtml(formatBytes(file.bytes ?? file.filesize))}
          </div>
          ${file.debrid_link ? `<div class="code-block muted url-truncated">${t("labels.debrid")}: ${escapeHtml(file.debrid_link)}</div>` : ""}
          ${file.download_url ? `<div class="code-block muted url-truncated">${t("labels.direct")}: ${escapeHtml(file.download_url)}</div>` : ""}
        </div>

        <div class="inline-actions">
          ${
            job.output_mode === "per_file" && file.debrid_link
              ? renderAsyncButton({
                  action: "unrestrict-file",
                  jobId: job.id,
                  fileId: file.id,
                  label: file.download_url ? t("job.unlock_again") : t("job.unrestrict"),
                })
              : ""
          }

          ${
            file.download_url
              ? renderAsyncButton({
                  action: "copy-file-url",
                  jobId: job.id,
                  fileId: file.id,
                  label: copyFileLabel,
                })
              : ""
          }
        </div>
      </div>
    `;
  }).join("");
}

function renderFilesBlock(job) {
  const filesCount = job.files?.length || 0;
  const defaultOpen = filesCount > 0 && filesCount <= 5;
  const filesOpen = isPanelOpen(job, "files", defaultOpen);

  return `
    <details class="detail-block collapsible-block" data-panel="files" ${filesOpen ? "open" : ""}>
      <summary>${t("job.files")} (${filesCount})</summary>
      <div class="collapsible-content">
        ${renderFiles(job.files, job)}
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
