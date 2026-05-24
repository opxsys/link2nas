import { ACTIVE_STATUSES, JOBS_POLL_MS } from "../../config.js";
import { state } from "../../state.js";
import { loadJobs, selectJob } from "../../actions/jobs.js";
import { loadSystemInfo } from "../../actions/system.js";
import { renderJobDetails } from "../../render/job-details.js";

export function startPolling() {
  clearInterval(state.jobsPollTimer);
  clearInterval(state.systemPollTimer);

  state.jobsPollTimer = setInterval(async () => {
    await loadJobs();

    if (!state.selectedJobId) return;

    const selectedFromList = state.jobs.find((job) => job.id === state.selectedJobId);

    if (!selectedFromList) {
      state.selectedJobId = null;
      state.selectedJob = null;
      renderJobDetails(null);
      return;
    }

    const selectedStatus = String(selectedFromList.status || "").trim().toLowerCase();
    const selectedDestinationStatus = String(selectedFromList.destination_status || "").trim().toLowerCase();

    const shouldRefreshDetails =
      ACTIVE_STATUSES.has(selectedStatus) ||
      ["queued", "sending", "downloading", "cancel_requested"].includes(selectedDestinationStatus) ||
      selectedStatus === "cancelled" ||
      state.selectedJob?.status !== selectedFromList.status ||
      state.selectedJob?.destination_status !== selectedFromList.destination_status ||
      state.selectedJob?.destination_progress !== selectedFromList.destination_progress ||
      state.selectedJob?.updated_at !== selectedFromList.updated_at;

    if (shouldRefreshDetails) {
      await selectJob(state.selectedJobId);
    }
  }, JOBS_POLL_MS);

  state.systemPollTimer = setInterval(async () => {
    await loadSystemInfo();
  }, JOBS_POLL_MS);
}
