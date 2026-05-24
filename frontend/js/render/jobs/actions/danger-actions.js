import { t } from "../../../i18n/index.js";
import { renderAsyncButton } from "./async-button.js";

export function renderJobDangerActions(job, capabilities) {
  const { canCancelLocalDownload, canCancel } = capabilities;

  return `
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
      </div>`;
}
