import {
  getJob,
  getJobs,
  ApiError,
} from "../../api.js";
import { state } from "../../state.js";
import { renderJobsList } from "../../render/jobs-list.js";
import { renderJobDetails } from "../../render/job-details.js";
import { showAppMessage } from "../../utils.js";
import { t } from "../../i18n/index.js";
import {
  ensureRestartCooldownsLoaded,
  buildActionKey,
  setCurrentAction,
  clearCurrentAction,
  isRestartCooldownError,
} from "./state-helpers.js";
import { handleLifecycleJobAction } from "./lifecycle-actions.js";
import { handleFileJobAction } from "./file-actions.js";
import { handleDestinationJobAction } from "./destination-actions.js";
import { handleProviderJobAction } from "./provider-actions.js";
import { handleCopyJobAction } from "./copy-actions.js";

async function reloadJobs() {
  await ensureRestartCooldownsLoaded(true);
  state.jobs = await getJobs(state.jobsStatusFilter);
  renderJobsList(state.jobs, state.selectedJobId);
}

async function selectJob(jobId) {
  state.selectedJobId = jobId;
  state.selectedJob = await getJob(jobId);
  renderJobsList(state.jobs, state.selectedJobId);
  renderJobDetails(state.selectedJob);
}

export async function performJobAction(action, jobId, fileId = null) {
  const actionKey = buildActionKey(action, jobId, fileId);

  try {
    setCurrentAction(action, jobId, fileId);
    renderJobDetails(state.selectedJob);

    if (await handleLifecycleJobAction(action, jobId, { reloadJobs, selectJob })) return;
    if (await handleFileJobAction(action, jobId, fileId, { reloadJobs, selectJob })) return;
    if (await handleDestinationJobAction(action, jobId, { reloadJobs, selectJob })) return;
    if (await handleProviderJobAction(action, jobId, { reloadJobs, selectJob })) return;
    if (await handleCopyJobAction(action, jobId, fileId, { selectJob })) return;
  } catch (error) {
    if (action === "restart" && isRestartCooldownError(error)) {
      showAppMessage(error.message, "info");
      return;
    }

    const message =
      error instanceof ApiError
        ? error.message
        : error?.message || "Unexpected error";

    showAppMessage(message, "error");
  } finally {
    if (state.currentActionKey === actionKey) {
      clearCurrentAction();
      renderJobDetails(state.selectedJob);
    }
  }
}
