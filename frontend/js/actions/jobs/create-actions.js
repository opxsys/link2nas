import { createJobsBulk, createTorrentFileJob, getJob, getJobs } from "../../api.js";
import { state } from "../../state.js";
import { renderJobsList } from "../../render/jobs-list.js";
import { renderJobDetails } from "../../render/job-details.js";
import { showAppMessage } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { ensureRestartCooldownsLoaded } from "./state-helpers.js";

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

export async function createNewJob(payload) {
  if (payload.source_type === "torrent_file") {
    const result = await createTorrentFileJob(
      payload.file,
      Boolean(payload.auto_start),
      Boolean(payload.send_to_destination),
      payload.provider_config_id || payload.provider_name || null,
      payload.destination_config_id || payload.destination_name || null
    );
    const job = result.job;
    const reused = result.reused;

    await reloadJobs();
    await selectJob(job.id);

    if (reused) {
      showAppMessage(t("messages.torrent_job_reused"), "info");
    } else if (payload.auto_start && payload.send_to_destination) {
      showAppMessage(t("messages.torrent_job_created_started_destination"), "success");
    } else if (payload.auto_start) {
      showAppMessage(t("messages.torrent_job_created_started"), "success");
    } else if (payload.send_to_destination) {
      showAppMessage(t("messages.torrent_job_created_destination"), "success");
    } else {
      showAppMessage(t("messages.torrent_job_created"), "success");
    }

    return;
  }

  const result = await createJobsBulk(
    payload.source_value,
    Boolean(payload.auto_start),
    Boolean(payload.send_to_destination),
    payload.provider_config_id || payload.provider_name || null,
    payload.destination_config_id || payload.destination_name || null
  );

  const entries = result.jobs || [];

  await reloadJobs();

  if (entries.length > 0) {
    const lastJob = entries[entries.length - 1].job;
    await selectJob(lastJob.id);
  }

  return entries;
}

export async function createTorrentFilesBatch({
  files,
  autoStart = false,
  sendToDestination = false,
  providerConfigId = null,
  destinationConfigId = null,
}) {
  const results = [];
  const fileList = Array.from(files || []);

  for (const file of fileList) {
    try {
      const result = await createTorrentFileJob(
        file,
        Boolean(autoStart),
        Boolean(sendToDestination),
        providerConfigId,
        destinationConfigId
      );

      const job = result.job;
      const itemError =
        result.error ||
        job?.error_message ||
        (job?.status === "failed" ? "Job failed" : "");

      results.push({
        filename: file.name,
        ok: !itemError,
        error: itemError || null,
        job,
        job_id: job?.id,
        reused: Boolean(result.reused),
      });
    } catch (error) {
      results.push({
        filename: file.name,
        ok: false,
        error: error.message || "Erreur création job",
      });
    }
  }

  await reloadJobs();

  const lastSuccess = [...results].reverse().find((item) => item.ok && item.job_id);
  if (lastSuccess?.job_id) {
    await selectJob(lastSuccess.job_id);
  }

  return results;
}
