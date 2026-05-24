import { t } from "../../../i18n/index.js";
import { normalizeDestinationName } from "../utils.js";
import {
  getOtherProviders,
  getRealDestinations,
  getRestartCooldownRemaining,
} from "./helpers.js";

export function getJobActionCapabilities(job) {
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

  return {
    status,
    restartCooldownRemaining,
    canStart,
    canRestart,
    canRefresh,
    canSelectFiles,
    canResyncProvider,
    canShowGlobalUnrestrict,
    canCopySingle,
    canCopyAll,
    canSendDirectToDestination,
    canChooseSendDestination,
    canResendToDestination,
    canSendToOtherDestination,
    canCancel,
    canCloneWithOtherProvider,
    canCancelLocalDownload,
    copyDownloadUrlLabel,
    copyAllDownloadsLabel,
  };
}
