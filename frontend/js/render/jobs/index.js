import { escapeHtml, formatBytes, formatDate, statusBadgeClass, formatJobStatus } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { state } from "../../state.js";
import { buildActionKey, normalizeDestinationName } from "./utils.js";

function resolveTranslatedMessage(key, params, fallback = "") {
  if (key) {
    return t(key, params || {});
  }
  return fallback || "";
}

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

function isActionLoading(action, jobId, fileId = null) {
  return state.currentActionKey === buildActionKey(action, jobId, fileId);
}

function isAnyActionLoading() {
  return Boolean(state.currentActionKey);
}

function getLoadingLabel(action, defaultLabel) {
  const map = {
    start: t("common.starting"),
    refresh: t("common.refreshing"),
    "resync-provider": t("common.resyncing"),
    "select-files": t("common.selecting"),
    unrestrict: t("job.unrestricting"),
    "unrestrict-file": t("job.unrestricting"),
    "send-to-destination": t("job.sending_to_destination"),
    "resend-to-destination": t("job.sending_to_destination"),
    "send-to-other-destination": t("job.sending_to_destination"),
    "cancel-local-download": t("common.cancelling_local"),
    "clone-with-provider": t("job.clone_with_provider_loading"),
    "copy-download-url": t("job.copying_link"),
    "copy-all-downloads": t("job.copying_links"),
    "copy-file-url": t("common.copying"),
    cancel: t("common.cancelling"),
    restart: t("common.restarting"),
    delete: t("common.deleting"),
  };

  return map[action] || defaultLabel;
}

function renderAsyncButton({ action, jobId, label, fileId = null, extraClass = "", disabled = false }) {
  const loading = isActionLoading(action, jobId, fileId);
  const finalDisabled = disabled || loading;
  const finalLabel = loading ? getLoadingLabel(action, label) : label;
  const classAttr = extraClass ? `btn ${extraClass}` : "btn";

  return `<button class="${classAttr}" data-action="${escapeHtml(action)}" data-job-id="${escapeHtml(jobId)}"${fileId != null ? ` data-file-id="${escapeHtml(fileId)}"` : ""}${finalDisabled ? " disabled" : ""}>${escapeHtml(finalLabel)}</button>`;
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

function formatDestinationStatus(job) {
  const status = String(job.destination_status || "").trim().toLowerCase();

  const destinationType = String(
    job.destination_type || job.destination_name || ""
  ).trim().toLowerCase();

  if (!status) return t("common.none");

  if (status === "sent") {
    if (destinationType === "local") return t("destination.status.saved_local");
    return t("destination.status.sent");
  }

  if (status === "queued") return t("job.local_status.queued");
  if (status === "downloading") return t("job.local_status.downloading");
  if (status === "cancel_requested") return t("job.local_status.cancel_requested");
  if (status === "cancelled") return t("job.local_status.cancelled");
  if (status === "sending") return t("destination.status.sending");
  if (status === "failed") return t("destination.status.failed");
  if (status === "pending") return t("destination.status.pending");

  return status;
}

function hasRealDestination(job) {
  const value = String(job.destination_type || job.destination_name || "").trim().toLowerCase();
  return value === "synology" || value === "nas" || value === "local";
}

function getSendDestinationLabel(job) {
  const value = String(job.destination_type || job.destination_name || "").trim().toLowerCase();

  if (value === "synology" || value === "nas") return t("job.send_to_nas");
  if (value === "local") return t("job.send_to_local");

  return t("job.send_to_destination");
}

function getResendDestinationLabel(job) {
  const value = String(job.destination_type || job.destination_name || "").trim().toLowerCase();

  if (value === "synology" || value === "nas") return t("job.resend_to_nas");
  if (value === "local") return t("job.resend_to_local");

  return t("job.resend_to_destination");
}

function getOtherProviders(job) {
  const providerConfigs = Array.isArray(job.active_provider_configs)
    ? job.active_provider_configs
    : [];

  if (providerConfigs.length) {
    return providerConfigs.filter((provider) => provider.id !== job.provider_config_id);
  }

  const providers = Array.isArray(job.active_provider_names)
    ? job.active_provider_names
    : [];

  return providers.filter((providerName) => providerName !== job.provider_name);
}

function getRealDestinations(job) {
  const destinationConfigs = Array.isArray(job.active_real_destination_configs)
    ? job.active_real_destination_configs
    : [];

  // V3 action rendering must only use real active destination profiles.
  // Do not fallback to active_real_destination_names, because legacy technical
  // names can recreate fake destinations like "local" or "synology".
  return destinationConfigs
    .filter((destination) => destination.id)
    .map((destination) => ({
      id: destination.id,
      destination_type: normalizeDestinationName(destination.destination_type || destination.destination_name),
    }))
    .filter((destination) => ["synology", "local"].includes(destination.destination_type));
}

function canUseOtherDestination(job) {
  const destinations = getRealDestinations(job);
  const currentDestination = job.destination_config_id || normalizeDestinationName(
    job.destination_name || job.destination_type
  );

  if (!destinations.length) {
    return false;
  }

  if (!currentDestination) {
    return destinations.length > 0;
  }

  return destinations.some((destination) => {
    if (typeof destination === "object") {
      return destination.id !== currentDestination;
    }
    return destination !== currentDestination;
  });
}

function getRestartCooldownSeconds(job) {
  const provider = String(job?.provider_name || "").trim().toLowerCase();
  const cfg = state.restartCooldowns || {};

  if (provider === "realdebrid") {
    return Number(
      cfg.realdebrid_seconds ??
      cfg.realdebrid ??
      cfg.default_seconds ??
      cfg.default ??
      60
    );
  }

  if (provider === "alldebrid") {
    return Number(
      cfg.alldebrid_seconds ??
      cfg.alldebrid ??
      cfg.default_seconds ??
      cfg.default ??
      8
    );
  }

  return Number(
    cfg.default_seconds ??
    cfg.default ??
    10
  );
}

function getRestartCooldownRemaining(job) {
  const status = String(job?.status || "").trim().toLowerCase();
  if (status !== "cancelled") return 0;

  const cancelledAt = String(job?.cancelled_at || "").trim();
  if (!cancelledAt) return 0;

  const cancelledDate = new Date(cancelledAt);
  if (Number.isNaN(cancelledDate.getTime())) return 0;

  const cooldownSeconds = getRestartCooldownSeconds(job);
  const elapsedSeconds = Math.floor((Date.now() - cancelledDate.getTime()) / 1000);

  return Math.max(0, cooldownSeconds - elapsedSeconds);
}

function getRestartLabel(job) {
  const remaining = getRestartCooldownRemaining(job);
  if (remaining <= 0) return t("common.restart");
  return `${t("common.restart")} (${remaining}s)`;
}

function renderJobMessage(job) {
  const status = String(job.status || "").trim().toLowerCase();
  const hasError = Boolean(job.error_message);

  const message = resolveTranslatedMessage(
    job.last_message_key,
    job.last_message_params,
    job.last_message || job.error_message
  );

  if (!message) return "";
  if (status === "completed" && !hasError) return "";

  return `
    <div class="job-message-banner ${hasError ? "is-error" : "is-info"}">
      ${escapeHtml(message)}
    </div>
  `;
}

function renderJobActions(job) {
  const status = String(job.status || "").trim().toLowerCase();
  const restartCooldownRemaining = getRestartCooldownRemaining(job);

  const canStart = status === "created";
  const canRestart = ["cancelled", "failed"].includes(status);

  const canRefresh = [
    "started",
    "source_added",
    "waiting_files_selection",
    "downloading",
    "downloaded",
    "ready",
    "partially_ready",
  ].includes(status);

  const canSelectFiles = status === "waiting_files_selection";
  const canResyncProvider = status === "failed" && Boolean(job.torrent_id);

  const canShowGlobalUnrestrict =
    ["downloaded", "ready", "completed"].includes(status) &&
    job.output_mode !== "per_file" &&
    (Boolean(job.debrid_link) || (job.source_type === "direct_link" && Boolean(job.source_value)));

  const canCopySingle = Boolean(job.download_url) && job.output_mode !== "per_file";
  const canCopyAll = job.output_mode === "per_file" && (job.files || []).some((file) => file.download_url);

  const availableDestinations = getRealDestinations(job);
  const currentDestination = job.destination_config_id || normalizeDestinationName(
    job.destination_name || job.destination_type
  );

  const hasCurrentDestination = Boolean(currentDestination);
  const hasOneDestination = availableDestinations.length === 1;
  const hasMultipleDestinations = availableDestinations.length > 1;

  const canUseDestination = availableDestinations.length > 0;
  const canUseReadyDestinationAction =
    canUseDestination &&
    ["ready", "partially_ready", "completed"].includes(status);

  const canSendDirectToDestination =
    canUseReadyDestinationAction &&
    !job.sent_to_destination &&
    (
      hasCurrentDestination ||
      hasOneDestination
    );

  const canChooseSendDestination =
    canUseReadyDestinationAction &&
    !job.sent_to_destination &&
    !hasCurrentDestination &&
    hasMultipleDestinations;

  const canResendToDestination =
    canUseReadyDestinationAction &&
    job.sent_to_destination &&
    hasCurrentDestination &&
    Boolean(job.destination_available);

  const canSendToOtherDestination =
    canUseReadyDestinationAction &&
    (
      job.sent_to_destination ||
      hasCurrentDestination
    ) &&
    availableDestinations.some((destination) => {
      if (typeof destination === "object") {
        return destination.id !== currentDestination;
      }
      return destination !== currentDestination;
    });


  const canCancel = [
    "created",
    "queued",
    "starting",
    "started",
    "source_added",
    "waiting_files_selection",
    "downloading",
  ].includes(status);

  const canCloneWithOtherProvider =
    Boolean(job.provider_available) &&
    Boolean(job.can_clone_with_other_provider) &&
    getOtherProviders(job).length > 0 &&
    ["created", "failed", "cancelled", "ready", "partially_ready", "completed"].includes(status);

  const destinationStatus = String(job.destination_status || "").trim().toLowerCase();

  const destinationName = String(job.destination_name || job.destination_type || "")
    .trim()
    .toLowerCase();

  const canCancelLocalDownload =
    destinationName === "local" &&
    ["queued", "sending", "downloading", "cancel_requested"].includes(destinationStatus) &&
    !job.sent_to_destination;

  const copyDownloadUrlLabel = job._copyDownloadUrlDone ? t("job.copy_link_done") : t("job.copy_link");
  const copyAllDownloadsLabel = job._copyAllDownloadsDone ? t("job.copy_all_links_done") : t("job.copy_all_links");

  return `
    <div class="job-actions">
      <div class="job-actions-main inline-actions">
        ${canStart ? renderAsyncButton({ action: "start", jobId: job.id, label: t("common.start") }) : ""}
        ${canRefresh ? renderAsyncButton({ action: "refresh", jobId: job.id, label: t("common.refresh") }) : ""}
        ${canResyncProvider ? renderAsyncButton({ action: "resync-provider", jobId: job.id, label: t("common.resync_provider") }) : ""}
        ${canSelectFiles ? renderAsyncButton({ action: "select-files", jobId: job.id, label: t("common.select_all") }) : ""}

        ${
          canShowGlobalUnrestrict
            ? renderAsyncButton({
                action: "unrestrict",
                jobId: job.id,
                label: job.download_url ? t("job.unlock_again") : t("job.unrestrict"),
              })
            : ""
        }

        ${
          canCopySingle
            ? renderAsyncButton({
                action: "copy-download-url",
                jobId: job.id,
                label: copyDownloadUrlLabel,
              })
            : ""
        }

        ${
          canCopyAll
            ? renderAsyncButton({
                action: "copy-all-downloads",
                jobId: job.id,
                label: copyAllDownloadsLabel,
              })
            : ""
        }

        ${
          canSendDirectToDestination
            ? renderAsyncButton({
                action: "send-to-destination",
                jobId: job.id,
                label: getSendDestinationLabel(job),
              })
            : ""
        }

        ${
          canChooseSendDestination
            ? renderAsyncButton({
                action: "send-to-other-destination",
                jobId: job.id,
                label: t("job.send_to_destination"),
              })
            : ""
        }

        ${
          canResendToDestination
            ? renderAsyncButton({
                action: "resend-to-destination",
                jobId: job.id,
                label: getResendDestinationLabel(job),
              })
            : ""
        }

        ${
          canSendToOtherDestination
            ? renderAsyncButton({
                action: "send-to-other-destination",
                jobId: job.id,
                label: job.sent_to_destination
                  ? t("job.resend_to_other_destination")
                  : t("job.send_to_other_destination"),
              })
            : ""
        }

        ${
          canCloneWithOtherProvider
            ? renderAsyncButton({
                action: "clone-with-provider",
                jobId: job.id,
                label: t("job.clone_with_other_provider"),
              })
            : ""
        }

        ${
          canRestart
            ? renderAsyncButton({
                action: "restart",
                jobId: job.id,
                label: getRestartLabel(job),
                disabled: restartCooldownRemaining > 0,
              })
            : ""
        }
      </div>

      <div class="job-actions-danger inline-actions">
        ${
          canCancelLocalDownload
            ? renderAsyncButton({
                action: "cancel-local-download",
                jobId: job.id,
                label: t("job.cancel_local_download"),
                extraClass: "btn-danger",
              })
            : ""
        }

        ${
          canCancel
            ? renderAsyncButton({
                action: "cancel",
                jobId: job.id,
                label: t("common.cancel"),
                extraClass: "btn-danger",
              })
            : ""
        }

        ${renderAsyncButton({ action: "delete", jobId: job.id, label: t("common.delete"), extraClass: "btn-danger" })}
      </div>
    </div>
  `;
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
