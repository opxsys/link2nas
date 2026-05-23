import {
  cancelJob,
  createJobsBulk,
  createTorrentFileJob,
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
  resyncProvider,
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

let jobsRefreshRunning = false;
let jobDetailsRefreshRunning = false;

function openModal({ title, bodyHtml, confirmLabel = "Valider", cancelLabel = "Annuler" }) {
  return new Promise((resolve) => {
    const modal = document.getElementById("app-modal");
    const titleEl = document.getElementById("app-modal-title");
    const bodyEl = document.getElementById("app-modal-body");
    const confirmBtn = document.getElementById("app-modal-confirm");
    const cancelBtn = document.getElementById("app-modal-cancel");

    if (!modal || !titleEl || !bodyEl || !confirmBtn || !cancelBtn) {
      resolve(null);
      return;
    }

    titleEl.textContent = title;
    bodyEl.innerHTML = bodyHtml;
    confirmBtn.textContent = confirmLabel;
    cancelBtn.textContent = cancelLabel;

    modal.hidden = false;

    const cleanup = (value) => {
      modal.hidden = true;
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      modal.onclick = null;
      resolve(value);
    };

    confirmBtn.onclick = () => cleanup(true);
    cancelBtn.onclick = () => cleanup(false);

    modal.onclick = (event) => {
      if (event.target === modal) {
        cleanup(false);
      }
    };
  });
}

async function confirmModal(title, message, confirmLabel = "Confirmer") {
  return openModal({
    title,
    bodyHtml: `<p class="muted">${message}</p>`,
    confirmLabel,
  });
}

function normalizeSelectOption(option) {
  if (typeof option === "object" && option !== null) {
    return {
      value: String(option.value ?? option.id ?? ""),
      label: String(option.label ?? option.name ?? option.value ?? option.id ?? ""),
    };
  }

  return {
    value: String(option),
    label: String(option),
  };
}

async function selectModal(title, label, values, defaultValue = "") {
  if (!values.length) {
    return null;
  }

  const normalizedOptions = values.map(normalizeSelectOption);
  const defaultOptionValue = typeof defaultValue === "object" && defaultValue !== null
    ? String(defaultValue.value ?? defaultValue.id ?? "")
    : String(defaultValue || "");

  const optionsHtml = normalizedOptions.map((option) => `
    <option value="${option.value}" ${option.value === defaultOptionValue ? "selected" : ""}>
      ${option.label}
    </option>
  `).join("");

  const confirmed = await openModal({
    title,
    bodyHtml: `
      <label class="form-grid">
        <span>${label}</span>
        <select id="app-modal-select">
          ${optionsHtml}
        </select>
      </label>
    `,
    confirmLabel: "Valider",
  });

  if (!confirmed) {
    return null;
  }

  return document.getElementById("app-modal-select")?.value || null;
}

function getDestinationLabel(destination) {
  const name = String(destination?.name || destination?.destination_profile_name || "").trim();
  const type = String(destination?.destination_type || destination?.destination_name || "").trim();

  if (name && type) return `${name} (${type})`;
  return name || type || String(destination?.id || "");
}

async function selectDestinationConfigModal(title, label, destinations, defaultId = "") {
  if (!destinations.length) return null;

  const optionsHtml = destinations.map((destination) => {
    const id = String(destination.id || "");
    return `
      <option value="${id}" ${id === defaultId ? "selected" : ""}>
        ${getDestinationLabel(destination)}
      </option>
    `;
  }).join("");

  const confirmed = await openModal({
    title,
    bodyHtml: `
      <label class="form-grid">
        <span>${label}</span>
        <select id="app-modal-select">
          ${optionsHtml}
        </select>
      </label>
    `,
    confirmLabel: "Valider",
  });

  if (!confirmed) return null;

  return document.getElementById("app-modal-select")?.value || null;
}


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

    await loadJobs();
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

  await loadJobs();

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

  await loadJobs();

  const lastSuccess = [...results].reverse().find((item) => item.ok && item.job_id);
  if (lastSuccess?.job_id) {
    await selectJob(lastSuccess.job_id);
  }

  return results;
}
function formatProviderType(providerType) {
  const value = String(providerType || "").trim().toLowerCase();
  if (value === "realdebrid") return "RealDebrid";
  if (value === "alldebrid") return "AllDebrid";
  return providerType || "-";
}

function formatDestinationType(destinationType) {
  const value = String(destinationType || "").trim().toLowerCase();
  if (value === "synology" || value === "nas") return "NAS Synology";
  if (value === "local") return "Local";
  return destinationType || "-";
}

function providerOption(config) {
  return {
    value: config.id,
    label: `${config.name || formatProviderType(config.provider_type || config.provider_name)} (${formatProviderType(config.provider_type || config.provider_name)})`,
  };
}

function destinationOption(config) {
  return {
    value: config.id,
    label: `${config.name || formatDestinationType(config.destination_type || config.destination_name)} (${formatDestinationType(config.destination_type || config.destination_name)})`,
  };
}

function getActiveDestinationConfigs(job) {
  const configs = Array.isArray(job?.active_real_destination_configs)
    ? job.active_real_destination_configs
    : [];

  // V3 actions must only use real active destination profiles.
  // Do not fallback to active_real_destination_names here, because those are
  // legacy technical names and can recreate fake destinations like "local".
  return configs.filter((config) => config?.id);
}

function getOtherDestinationConfigs(job) {
  return getActiveDestinationConfigs(job).filter((config) => {
    if (job?.destination_config_id) {
      return config.id !== job.destination_config_id;
    }

    return (config.destination_type || config.destination_name) !== job?.destination_name;
  });
}

function getOtherProviderConfigs(job) {
  const configs = Array.isArray(job?.active_provider_configs)
    ? job.active_provider_configs
    : [];

  if (configs.length) {
    return configs.filter((config) => config?.id && config.id !== job?.provider_config_id);
  }

  return (job?.active_provider_names || [])
    .filter((providerName) => providerName !== job?.provider_name)
    .map((providerName) => ({
      id: providerName,
      name: providerName,
      provider_type: providerName,
      provider_name: providerName,
    }));
}

export async function performJobAction(action, jobId, fileId = null) {
  const actionKey = buildActionKey(action, jobId, fileId);

  try {
    setCurrentAction(action, jobId, fileId);
    renderJobDetails(state.selectedJob);

    if (action === "start") {
      await startJob(jobId);
      showAppMessage(t("messages.job_started"), "success");
      await loadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "refresh" || action === "resync-provider") {
      await refreshJob(jobId);
      await loadJobs();
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
      await loadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "restart") {
      await restartJob(jobId);
      showAppMessage(t("messages.job_restarted"), "success");
      await loadJobs();
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

      await loadJobs();

      if (wasSelected) {
        renderJobDetails(null);
      }

      showAppMessage(t("messages.job_deleted"), "success");
      return;
    }

    if (action === "select-files") {
      await selectJobFiles(jobId, "all");
      showAppMessage(t("messages.select_all_done"), "success");
      await loadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "unrestrict") {
      await unrestrictJob(jobId);
      showAppMessage(t("messages.unrestrict_done"), "success");
      await loadJobs();
      await selectJob(jobId);
      return;
    }

    if (action === "unrestrict-file" && fileId != null) {
      forceOpenJobPanel(jobId, "files");
      await unrestrictJobFile(jobId, fileId);
      showAppMessage(t("messages.unrestrict_file_done"), "success");
      await loadJobs();
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
      await loadJobs();
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
      await loadJobs();
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
      await loadJobs();
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
      await loadJobs();
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

      await loadJobs();

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
