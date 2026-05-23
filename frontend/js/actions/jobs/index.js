import { getJob, getJobs } from "../../api.js";
import { state } from "../../state.js";
import { renderJobsList } from "../../render/jobs-list.js";
import { renderJobDetails } from "../../render/job-details.js";
import { ensureRestartCooldownsLoaded } from "./state-helpers.js";
export { createNewJob, createTorrentFilesBatch } from "./create-actions.js";
export { performJobAction } from "./perform-action.js";

let jobsRefreshRunning = false;
let jobDetailsRefreshRunning = false;

export async function loadJobs() {
  if (jobsRefreshRunning) return;

    await ensureRestartCooldownsLoaded(true);

  jobsRefreshRunning = true;

  try {
    state.jobs = await getJobs(state.jobsStatusFilter);
    renderJobsList(state.jobs, state.selectedJobId);
  } finally {
    jobsRefreshRunning = false;
  }
}

export async function selectJob(jobId) {
  state.selectedJobId = jobId;
  state.selectedJob = await getJob(jobId);
  renderJobsList(state.jobs, state.selectedJobId);
  renderJobDetails(state.selectedJob);
}

export async function refreshSelectedJob() {
  if (!state.selectedJobId || jobDetailsRefreshRunning) return;

  jobDetailsRefreshRunning = true;

  try {
    state.selectedJob = await getJob(state.selectedJobId);
    renderJobDetails(state.selectedJob);
  } finally {
    jobDetailsRefreshRunning = false;
  }
}
