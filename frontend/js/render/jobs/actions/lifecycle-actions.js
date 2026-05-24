import { t } from "../../../i18n/index.js";
import { renderAsyncButton } from "./async-button.js";
import { getRestartLabel } from "./helpers.js";

export function renderJobLifecycleActions(job, capabilities) {
  const { canCloneWithOtherProvider, canRestart, restartCooldownRemaining } = capabilities;

  return `
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
        }`;
}
