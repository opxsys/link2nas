import { t } from "../../../i18n/index.js";
import { renderAsyncButton } from "./async-button.js";
import { getSendDestinationLabel, getResendDestinationLabel } from "./helpers.js";

export function renderJobDestinationActions(job, capabilities) {
  const {
    canSendDirectToDestination,
    canChooseSendDestination,
    canResendToDestination,
    canSendToOtherDestination,
  } = capabilities;

  return `
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
        }`;
}
