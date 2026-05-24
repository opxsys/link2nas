import { ACTIVE_STATUSES, JOBS_POLL_MS } from "../../config.js";
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
import { loadSystemInfo } from "../../actions/system.js";
import { renderCreateJobForm, updateCreateJobDestinationVisibility } from "../../render/forms.js";
import { renderJobDetails } from "../../render/job-details.js";
import { setActivePage } from "../navigation-controller.js";

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

export function showBatchResultPanel(results) {
  document.getElementById("batch-result-panel")?.remove();

  const okCount = results.filter((r) => r.ok).length;

  const panel = document.createElement("div");
  panel.id = "batch-result-panel";
  panel.className = "batch-result-panel";

  const title = document.createElement("div");
  title.className = "batch-result-title";
  title.textContent = t("batch.result_title");
  panel.appendChild(title);

  const list = document.createElement("ul");
  list.className = "batch-result-list";
  for (const item of results) {
    const li = document.createElement("li");
    li.className = `batch-result-item ${item.ok ? "is-ok" : "is-error"}`;

    const name = document.createElement("span");
    name.className = "batch-result-filename";
    name.textContent = `${item.ok ? "✓" : "✗"} ${item.filename}`;
    li.appendChild(name);

    if (item.ok && item.reused) {
      const note = document.createElement("span");
      note.className = "batch-result-error";
      note.textContent = t("batch.job_reused");
      li.appendChild(note);
    }

    if (!item.ok && item.error) {
      const err = document.createElement("span");
      err.className = "batch-result-error";
      err.textContent = item.error;
      li.appendChild(err);
    }

    list.appendChild(li);
  }
  panel.appendChild(list);

  const actions = document.createElement("div");
  actions.className = "batch-result-actions";

  if (okCount > 0) {
    const viewBtn = document.createElement("button");
    viewBtn.type = "button";
    viewBtn.className = "btn btn-primary";
    viewBtn.textContent = t("batch.view_jobs");
    viewBtn.addEventListener("click", () => {
      panel.remove();
      setActivePage("jobs");
    });
    actions.appendChild(viewBtn);
  }

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "btn";
  closeBtn.textContent = t("batch.close");
  closeBtn.addEventListener("click", () => panel.remove());
  actions.appendChild(closeBtn);

  panel.appendChild(actions);
  const inlineContainer = document.getElementById("create-job-result-panel");
  if (inlineContainer) {
    panel.classList.add("is-inline");
    inlineContainer.innerHTML = "";
    inlineContainer.appendChild(panel);
  } else {
    document.body.appendChild(panel);
  }
}

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
