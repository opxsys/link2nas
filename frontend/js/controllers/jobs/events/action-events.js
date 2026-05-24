import { performJobAction } from "../../../actions/jobs.js";

export function bindJobActionEvents() {
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
}
