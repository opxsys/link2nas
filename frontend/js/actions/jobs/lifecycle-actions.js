import { startJob, refreshJob, cancelJob, restartJob, deleteJob } from "../../api.js";
import { state } from "../../state.js";
import { renderJobDetails } from "../../render/job-details.js";
import { showAppMessage } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { confirmModal } from "./modals.js";

export async function handleLifecycleJobAction(action, jobId, { reloadJobs, selectJob }) {
  if (action === "start") {
    await startJob(jobId);
    showAppMessage(t("messages.job_started"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "refresh" || action === "resync-provider") {
    await refreshJob(jobId);
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "cancel") {
    const confirmed = await confirmModal(
      "Annuler le job",
      "Annuler ce job et nettoyer les ressources provider si possible ?",
      "Annuler le job"
    );

    if (!confirmed) return true;

    await cancelJob(jobId);
    showAppMessage(t("messages.job_cancelled"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "restart") {
    await restartJob(jobId);
    showAppMessage(t("messages.job_restarted"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "delete") {
    const confirmed = await confirmModal(
      "Supprimer le job",
      t("messages.confirm_delete_job"),
      "Supprimer"
    );

    if (!confirmed) return true;

    const wasSelected = state.selectedJobId === jobId;
    await deleteJob(jobId);

    if (wasSelected) {
      state.selectedJobId = null;
      state.selectedJob = null;
    }

    await reloadJobs();

    if (wasSelected) {
      renderJobDetails(null);
    }

    showAppMessage(t("messages.job_deleted"), "success");
    return true;
  }

  return false;
}
