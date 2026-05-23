import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { saveDestination, deleteDestination, testDestination, testDestinationFromSettings } from "../../api.js";
import { fillDestinationForm, updateDestinationFields } from "../../render/settings.js";
import { showAppMessage } from "../../utils.js";
import { showDestinationFeedback } from "./feedback.js";
import { buildDestinationConfigJsonFromState } from "./payloads.js";
import { loadSettings } from "./loader.js";

export async function handleDestinationAction(action, button) {
  if (action === "toggle-destination-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const dest = state.destinations.find((d) => d.id === button.dataset.destinationId);
    if (!dest) { button.disabled = false; return true; }
    const payload = {
      destination_config_id: dest.id,
      destination_type: dest.destination_type || dest.destination_name,
      name: dest.name,
      config_json: buildDestinationConfigJsonFromState(dest),
      is_enabled: newEnabled,
      is_default: newEnabled ? dest.is_default : false,
    };
    try {
      await saveDestination(payload);
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_enabled_updated"), "success");
    } catch (err) {
      await loadSettings();
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "set-destination-default") {
    if (!button.checked) { button.checked = true; return true; }
    button.disabled = true;
    const dest = state.destinations.find((d) => d.id === button.dataset.destinationId);
    if (!dest) { button.disabled = false; return true; }
    const payload = {
      destination_config_id: dest.id,
      destination_type: dest.destination_type || dest.destination_name,
      name: dest.name,
      config_json: buildDestinationConfigJsonFromState(dest),
      is_enabled: true,
      is_default: true,
    };
    try {
      await saveDestination(payload);
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_default_updated"), "success");
    } catch (err) {
      await loadSettings();
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "cancel-destination-edit") {
    const form = document.getElementById("destination-form");
    if (!form) return true;
    form.reset();
    form.destination_config_id.value = "";
    form.querySelector("button[type='submit']").textContent = t("settings.destinations.save");
    button.hidden = true;
    updateDestinationFields();
    return true;
  }

  if (action === "edit-destination") {
    const destination = state.destinations.find((d) => d.id === button.dataset.destinationId);
    fillDestinationForm(destination);
    return true;
  }

  if (action === "test-destination") {
    try {
      const result = await testDestination(button.dataset.destinationId);
      await loadSettings();
      showDestinationFeedback(result.message || t("messages.settings_destination_tested"), "success");
    } catch (err) {
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "delete-destination") {
    try {
      await deleteDestination(button.dataset.destinationId);
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_deleted"), "success");
    } catch (err) {
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "test-destination-settings") {
    const result = await testDestinationFromSettings(button.dataset.destinationId);
    showAppMessage(result.message || t("messages.settings_destination_tested"), "success");
    return true;
  }

  return false;
}
