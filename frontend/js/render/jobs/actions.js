import { escapeHtml } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { state } from "../../state.js";
import { buildActionKey, normalizeDestinationName } from "./utils.js";

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

export function renderAsyncButton({ action, jobId, label, fileId = null, extraClass = "", disabled = false }) {
  const loading = isActionLoading(action, jobId, fileId);
  const finalDisabled = disabled || loading;
  const finalLabel = loading ? getLoadingLabel(action, label) : label;
  const classAttr = extraClass ? `btn ${extraClass}` : "btn";

  return `<button class="${classAttr}" data-action="${escapeHtml(action)}" data-job-id="${escapeHtml(jobId)}"${fileId != null ? ` data-file-id="${escapeHtml(fileId)}"` : ""}${finalDisabled ? " disabled" : ""}>${escapeHtml(finalLabel)}</button>`;
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

export function renderJobActions(job) {
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
