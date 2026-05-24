import { cloneJobWithProvider } from "../../api.js";
import { state } from "../../state.js";
import { showAppMessage } from "../../utils.js";
import { selectModal } from "./modals.js";
import { getOtherProviderConfigs, providerOption } from "./profile-helpers.js";

export async function handleProviderJobAction(action, jobId, { reloadJobs, selectJob }) {
  if (action === "clone-with-provider") {
    const job = state.selectedJob;
    const availableProviders = getOtherProviderConfigs(job);

    if (!availableProviders.length) {
      showAppMessage("Aucun autre provider disponible.", "info");
      return true;
    }

    const providerRef = await selectModal(
      "Dupliquer avec autre provider",
      "Provider cible",
      availableProviders.map(providerOption),
      availableProviders[0].id
    );

    if (!providerRef) return true;

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

    return true;
  }

  return false;
}
