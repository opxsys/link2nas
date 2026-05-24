import { renderAsyncButton } from "./async-button.js";
import { getJobActionCapabilities } from "./capabilities.js";
import { renderJobMainActions } from "./main-actions.js";
import { renderJobDestinationActions } from "./destination-actions.js";
import { renderJobLifecycleActions } from "./lifecycle-actions.js";
import { renderJobDangerActions } from "./danger-actions.js";

export { renderAsyncButton };

export function renderJobActions(job) {
  const capabilities = getJobActionCapabilities(job);
  const {
    canStart,
    canRefresh,
    canSelectFiles,
    canResyncProvider,
    canShowGlobalUnrestrict,
    canCopySingle,
    canCopyAll,
    copyDownloadUrlLabel,
    copyAllDownloadsLabel,
  } = capabilities;

  return `
    <div class="job-actions">
      <div class="job-actions-main inline-actions">
        ${renderJobMainActions(job, { canStart, canRefresh, canResyncProvider, canSelectFiles, canShowGlobalUnrestrict, canCopySingle, canCopyAll, copyDownloadUrlLabel, copyAllDownloadsLabel })}

        ${renderJobDestinationActions(job, capabilities)}

        ${renderJobLifecycleActions(job, capabilities)}
      </div>

      ${renderJobDangerActions(job, capabilities)}
    </div>
  `;
}
