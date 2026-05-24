import {
  sendJobToDestination,
  resendJobToDestination,
  cancelLocalDestinationDownload,
} from "../../api.js";
import { state } from "../../state.js";
import { showAppMessage } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { confirmModal, selectDestinationConfigModal } from "./modals.js";
import { getActiveDestinationConfigs } from "./profile-helpers.js";

export async function handleDestinationJobAction(action, jobId, { reloadJobs, selectJob }) {
  if (action === "send-to-destination") {
    const job = state.selectedJob;
    const destinations = getActiveDestinationConfigs(job);

    if (!destinations.length) {
      showAppMessage("Aucune destination configurée.", "info");
      return true;
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

      if (!destinationConfigId) return true;
    }

    await sendJobToDestination(jobId, destinationConfigId);
    showAppMessage(t("messages.destination_send_started"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "send-to-other-destination") {
    const job = state.selectedJob;
    const currentDestinationConfigId = String(job?.destination_config_id || "");

    const destinations = getActiveDestinationConfigs(job)
      .filter((destination) => String(destination.id || "") !== currentDestinationConfigId);

    if (!destinations.length) {
      showAppMessage("Aucune autre destination configurée.", "info");
      return true;
    }

    const destinationConfigId = await selectDestinationConfigModal(
      "Envoyer vers une autre destination",
      "Destination cible",
      destinations,
      destinations[0].id
    );

    if (!destinationConfigId) return true;

    await sendJobToDestination(jobId, destinationConfigId);
    showAppMessage(t("messages.destination_send_started"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "resend-to-destination") {
    const job = state.selectedJob;
    const destinations = getActiveDestinationConfigs(job);

    if (!destinations.length) {
      showAppMessage("Aucune destination configurée.", "info");
      return true;
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

      if (!destinationConfigId) return true;
    }

    await resendJobToDestination(jobId, destinationConfigId);
    showAppMessage(t("messages.destination_send_started"), "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  if (action === "cancel-local-download") {
    const confirmed = await confirmModal(
      "Annuler le téléchargement local",
      "Arrêter le téléchargement local en cours et supprimer le fichier partiel ?",
      "Annuler le téléchargement"
    );

    if (!confirmed) return true;

    await cancelLocalDestinationDownload(jobId);
    showAppMessage("Annulation du téléchargement local demandée.", "success");
    await reloadJobs();
    await selectJob(jobId);
    return true;
  }

  return false;
}
