import { t } from "../../../i18n/index.js";
import { normalizeDestinationName } from "../utils.js";
import { renderAsyncButton } from "./async-button.js";
import {
  getSendDestinationLabel,
  getResendDestinationLabel,
  getOtherProviders,
  getRealDestinations,
  getRestartCooldownRemaining,
  getRestartLabel,
} from "./helpers.js";

export { renderAsyncButton };

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
