import {
  cancelJob,
  deleteJob,
  getJob,
  getJobs,
  refreshJob,
  restartJob,
  selectJobFiles,
  sendJobToDestination,
  resendJobToDestination,
  startJob,
  unrestrictJob,
  unrestrictJobFile,
  cloneJobWithProvider,
  ApiError,
  cancelLocalDestinationDownload,
} from "../../api.js";
import { state } from "../../state.js";
import { renderJobsList } from "../../render/jobs-list.js";
import { renderJobDetails, forceOpenJobPanel } from "../../render/job-details.js";
import { showAppMessage, copyToClipboard } from "../../utils.js";
import { t } from "../../i18n/index.js";
import {
  ensureRestartCooldownsLoaded,
  buildActionKey,
  setCurrentAction,
  clearCurrentAction,
  clearCopyFlags,
  isRestartCooldownError,
} from "./state-helpers.js";
import {
  confirmModal,
  selectModal,
  selectDestinationConfigModal,
} from "./modals.js";
import {
  getActiveDestinationConfigs,
  getOtherProviderConfigs,
  providerOption,
} from "./profile-helpers.js";

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

    if (action === "start") {
      await startJob(jobId);
      showAppMessage(t("messages.job_started"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "refresh" || action === "resync-provider") {
      await refreshJob(jobId);
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "cancel") {
      const confirmed = await confirmModal(
        "Annuler le job",
        "Annuler ce job et nettoyer les ressources provider si possible ?",
        "Annuler le job"
      );

      if (!confirmed) return;

      await cancelJob(jobId);
      showAppMessage(t("messages.job_cancelled"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "restart") {
      await restartJob(jobId);
      showAppMessage(t("messages.job_restarted"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "delete") {
      const confirmed = await confirmModal(
        "Supprimer le job",
        t("messages.confirm_delete_job"),
        "Supprimer"
      );

      if (!confirmed) return;

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
      return;
    }

    if (action === "select-files") {
      await selectJobFiles(jobId, "all");
      showAppMessage(t("messages.select_all_done"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "unrestrict") {
      await unrestrictJob(jobId);
      showAppMessage(t("messages.unrestrict_done"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "unrestrict-file" && fileId != null) {
      forceOpenJobPanel(jobId, "files");
      await unrestrictJobFile(jobId, fileId);
      showAppMessage(t("messages.unrestrict_file_done"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "send-to-destination") {
      const job = state.selectedJob;
      const destinations = getActiveDestinationConfigs(job);

      if (!destinations.length) {
        showAppMessage("Aucune destination configurée.", "info");
        return;
      }

      let destinationConfigId = null;

      if (destinations.length === 1) {
        destinationConfigId = destinations[0].id;
      }

      if (destinations.length > 1 && !destinationConfigId) {
        destinationConfigId = await selectDestinationConfigModal(
          "Envoyer vers une destination",
          "Destination cible",
          destinations,
          destinations[0].id
        );

        if (!destinationConfigId) return;
      }

      await sendJobToDestination(jobId, destinationConfigId);
      showAppMessage(t("messages.destination_send_started"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "send-to-other-destination") {
      const job = state.selectedJob;
      const currentDestinationConfigId = String(job?.destination_config_id || "");

      const destinations = getActiveDestinationConfigs(job)
        .filter((destination) => String(destination.id || "") !== currentDestinationConfigId);

      if (!destinations.length) {
        showAppMessage("Aucune autre destination configurée.", "info");
        return;
      }

      const destinationConfigId = await selectDestinationConfigModal(
        "Envoyer vers une autre destination",
        "Destination cible",
        destinations,
        destinations[0].id
      );

      if (!destinationConfigId) return;

      await sendJobToDestination(jobId, destinationConfigId);
      showAppMessage(t("messages.destination_send_started"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "resend-to-destination") {
      const job = state.selectedJob;
      const destinations = getActiveDestinationConfigs(job);

      if (!destinations.length) {
        showAppMessage("Aucune destination configurée.", "info");
        return;
      }

      let destinationConfigId = null;

      if (job?.destination_available && job?.destination_config_id) {
        const currentDestination = destinations.find(
          (destination) => String(destination.id || "") === String(job.destination_config_id)
        );

        if (currentDestination) {
          destinationConfigId = currentDestination.id;
        }
      }

      if (!destinationConfigId && destinations.length === 1) {
        destinationConfigId = destinations[0].id;
      }

      if (!destinationConfigId) {
        destinationConfigId = await selectDestinationConfigModal(
          "Renvoyer vers une destination",
          "Destination cible",
          destinations,
          destinations[0].id
        );

        if (!destinationConfigId) return;
      }

      await resendJobToDestination(jobId, destinationConfigId);
      showAppMessage(t("messages.destination_send_started"), "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "cancel-local-download") {
      const confirmed = await confirmModal(
        "Annuler le téléchargement local",
        "Arrêter le téléchargement local en cours et supprimer le fichier partiel ?",
        "Annuler le téléchargement"
      );

      if (!confirmed) return;

      await cancelLocalDestinationDownload(jobId);
      showAppMessage("Annulation du téléchargement local demandée.", "success");
      await reloadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "clone-with-provider") {
      const job = state.selectedJob;
      const availableProviders = getOtherProviderConfigs(job);

      if (!availableProviders.length) {
        showAppMessage("Aucun autre provider disponible.", "info");
        return;
      }

      const providerRef = await selectModal(
        "Dupliquer avec autre provider",
        "Provider cible",
        availableProviders.map(providerOption),
        availableProviders[0].id
      );

      if (!providerRef) return;

      const result = await cloneJobWithProvider(
        jobId,
        providerRef,
        job?.send_to_destination ? (job?.destination_config_id || job?.destination_name) : null,
        true
      );

      const clonedJob = result.job;

      showAppMessage(
        result.reused
          ? "Job existant réutilisé avec ce provider."
          : "Job dupliqué avec autre provider.",
        result.reused ? "info" : "success"
      );

      await reloadJobs();

      if (clonedJob?.id) {
        await selectJob(clonedJob.id);
      }

      return;
    }

    if (action === "copy-download-url") {
      const job = state.selectedJob;

      if (!job?.download_url) {
        showAppMessage(t("messages.no_link_to_copy"), "info");
        return;
      }

      const ok = await copyToClipboard(job.download_url);

      if (ok) {
        clearCopyFlags(job);
        job._copyDownloadUrlDone = true;
        renderJobDetails(job);
      }

      showAppMessage(
        ok ? t("messages.link_copied") : t("messages.copy_error"),
        ok ? "success" : "error"
      );
      return;
    }

    if (action === "copy-all-downloads") {
      const job = state.selectedJob;

      const urls = (job.files || [])
        .map((f) => f.download_url)
        .filter(Boolean);

      if (urls.length === 0) {
        showAppMessage(t("messages.no_link_to_copy"), "info");
        return;
      }

      const ok = await copyToClipboard(urls.join("\n"));

      if (ok) {
        clearCopyFlags(job);
        job._copyAllDownloadsDone = true;
        forceOpenJobPanel(job.id, "files");
        renderJobDetails(job);
      }

      showAppMessage(
        ok ? t("messages.links_copied", { count: urls.length }) : t("messages.copy_error"),
        ok ? "success" : "error"
      );
      return;
    }

    if (action === "copy-file-url" && fileId != null) {
      const job = state.selectedJob;
      const file = (job.files || []).find((f) => String(f.id) === String(fileId));

      if (!file?.download_url) {
        showAppMessage(t("messages.file_link_unavailable"), "info");
        return;
      }

      const ok = await copyToClipboard(file.download_url);

      if (ok) {
        clearCopyFlags(job);
        file._copyDone = true;
        forceOpenJobPanel(job.id, "files");
        renderJobDetails(job);
      }

      showAppMessage(
        ok ? t("messages.link_copied") : t("messages.copy_error"),
        ok ? "success" : "error"
      );
      return;
    }
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
