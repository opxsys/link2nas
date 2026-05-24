import { state } from "../../../state.js";
import { loadJobs, selectJob } from "../../../actions/jobs.js";
import { renderJobDetails } from "../../../render/job-details.js";
import { setActivePage } from "../../navigation-controller.js";

export function bindJobSelectionEvents() {
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
