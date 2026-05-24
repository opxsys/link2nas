import { t } from "../../../i18n/index.js";
import { renderAsyncButton } from "./async-button.js";
import {
  getSendDestinationLabel,
  getResendDestinationLabel,
  getRestartLabel,
} from "./helpers.js";
import { getJobActionCapabilities } from "./capabilities.js";

export { renderAsyncButton };

export function renderJobActions(job) {
  const {
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
  } = getJobActionCapabilities(job);

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
