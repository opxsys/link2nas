import { getEnabledProviders } from "./provider-select.js";
import { getRealDestinations } from "./destination-select.js";
import { renderCreateJobNoProviderState } from "./create-job/empty-state.js";
import { bindTorrentDropzone } from "./create-job/dropzone.js";
import { renderCreateJobMainForm } from "./create-job/form.js";

export function updateCreateJobDestinationVisibility() {
  const form = document.getElementById("create-job-form");
  if (!form) return;

  const checkbox = form.send_to_destination;
  const wrap = document.getElementById("create-destination-select-wrap");

  if (!wrap || !checkbox) return;

  wrap.hidden = !checkbox.checked;
}

export function renderCreateJobForm() {
  const container = document.getElementById("create-job-panel");

  if (!container) return;

  const providers = getEnabledProviders();
  const realDestinations = getRealDestinations();
  const canCreate = providers.length > 0;

  if (!canCreate) {
    renderCreateJobNoProviderState(container);
    return;
  }

  renderCreateJobMainForm(container, { providers, realDestinations, canCreate });

  bindTorrentDropzone(container);
  updateCreateJobDestinationVisibility();
}
