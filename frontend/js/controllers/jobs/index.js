import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { showAppMessage } from "../../utils.js";
import {
  loadJobs,
  createNewJob,
  createTorrentFilesBatch,
  performJobAction,
  selectJob,
} from "../../actions/jobs.js";
import { renderCreateJobForm, updateCreateJobDestinationVisibility } from "../../render/forms.js";
import { renderJobDetails } from "../../render/job-details.js";
import { setActivePage } from "../navigation-controller.js";
import { showBatchResultPanel } from "./batch-result.js";
export { startPolling } from "./polling.js";
export { showBatchResultPanel };

export function bindJobsEvents() {
  document.getElementById("jobs-status-filter")?.addEventListener("change", async (event) => {
    state.jobsStatusFilter = event.target.value;
    await loadJobs();

    if (state.selectedJobId) {
      const stillThere = state.jobs.find((job) => job.id === state.selectedJobId);

      if (stillThere) {
        await selectJob(state.selectedJobId);
      } else {
        state.selectedJobId = null;
        state.selectedJob = null;
        renderJobDetails(null);
      }
    }
  });

  document.getElementById("create-job-panel")?.addEventListener("change", (event) => {
    if (event.target?.name === "send_to_destination") {
      updateCreateJobDestinationVisibility();
    }
  });

  document.getElementById("create-job-panel")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;

    const rawText = form.source_value.value;

    const sources = rawText
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

    const seen = new Set();
    const duplicateLines = sources.filter(line => {
      if (seen.has(line)) return true;
      seen.add(line);
      return false;
    });
    const uniqueSources = [...seen];
    const files = Array.from(form.torrent_file?.files || []);
    const file = files[0] || null;
    const invalidSources = uniqueSources.filter((line) => {
      return !line.startsWith("magnet:?")
        && !/^https?:\/\//i.test(line);
    });

    const validSources = uniqueSources.filter((line) => {
      return line.startsWith("magnet:?")
        || /^https?:\/\//i.test(line);
    });

    const invalidResults = invalidSources.map((line) => ({
      filename: line,
      ok: false,
      error: t("messages.invalid_source_line"),
    }));
    const duplicateResults = duplicateLines.map((line) => ({
      filename: line,
      ok: false,
      error: t("messages.duplicate_source_ignored"),
    }));

    let pendingBatchResults = null;

    if (validSources.length === 0 && !file) {
      if (invalidResults.length > 0 || duplicateResults.length > 0) {
        pendingBatchResults = [...invalidResults, ...duplicateResults];
      } else {
        showAppMessage(t("messages.no_valid_source"), "error");
        return;
      }
    } else {
      const sourceValue = validSources.join("\n");
      form.source_value.value = sourceValue;

      const autoStart = Boolean(form.auto_start?.checked);
      const sendToDestination = Boolean(form.send_to_destination?.checked);

      const providerConfigId = form.provider_config_id?.value || null;
      const destinationConfigId = sendToDestination
        ? (form.destination_config_id?.value || null)
        : null;

      if (sourceValue && file) {
        pendingBatchResults = [{
          filename: t("form.create_jobs"),
          ok: false,
          error: t("messages.choose_text_or_file"),
        }];
      }

      if (!sourceValue && !file) {
        showAppMessage(t("messages.provide_source"), "info");
        return;
      }

      if (pendingBatchResults === null && files.length > 0) {
        const results = await createTorrentFilesBatch({
          files,
          autoStart,
          sendToDestination,
          providerConfigId,
          destinationConfigId,
        });

        pendingBatchResults = results;
      } else if (pendingBatchResults === null) {
        const entries = await createNewJob({
          source_type: "bulk_text",
          source_value: sourceValue,
          auto_start: autoStart,
          send_to_destination: sendToDestination,
          provider_config_id: providerConfigId,
          destination_config_id: destinationConfigId,
        });

        const batchResults = (entries || []).map((entry) => ({
          filename: entry.job?.source_value || entry.job?.filename || entry.job?.id || "Source",
          ok: true,
          error: null,
          job: entry.job,
          job_id: entry.job?.id,
          reused: Boolean(entry.reused),
        }));

        pendingBatchResults = [...batchResults, ...invalidResults, ...duplicateResults];
      }
    }

    form.reset();
    renderCreateJobForm();

    if (pendingBatchResults?.length > 0) {
      showBatchResultPanel(pendingBatchResults);
    }

    if (form.auto_start) {
      form.auto_start.checked = true;
    }

    if (form.send_to_destination) {
      form.send_to_destination.checked = false;
    }

    setActivePage("jobs");
  });

  document.getElementById("jobs-list")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) return;

    const action = button.dataset.action;
    const jobId = button.dataset.jobId;

    if (action === "delete") {
      await performJobAction("delete", jobId);
    }
  });

  document.getElementById("job-details")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) return;

    const action = button.dataset.action;
    const jobId = button.dataset.jobId;
    const fileId = button.dataset.fileId;

    await performJobAction(action, jobId, fileId);
  });

  document.addEventListener("click", async (event) => {
    const card = event.target.closest(".job-card");
    if (!card) return;

    if (event.target.closest("button, input, select, textarea, label, details, summary, form")) return;

    const jobId = card.dataset.jobId;
    if (!jobId) return;

    await selectJob(jobId);

    setActivePage("jobs");
  });
}
