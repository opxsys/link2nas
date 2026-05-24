import { t } from "../../../i18n/index.js";
import { renderAsyncButton } from "./async-button.js";

export function renderJobMainActions(job, capabilities) {
  const {
    canStart,
    canRefresh,
    canResyncProvider,
    canSelectFiles,
    canShowGlobalUnrestrict,
    canCopySingle,
    canCopyAll,
    copyDownloadUrlLabel,
    copyAllDownloadsLabel,
  } = capabilities;

  return `
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
        }`;
}
