import { t } from "../../i18n/index.js";
import { saveDestination } from "../../api.js";
import { showDestinationFeedback } from "./feedback.js";
import { buildDestinationConfig } from "./payloads.js";
import { loadSettings } from "./loader.js";

export async function handleDestinationSubmit(form) {
  if (form.id === "destination-form") {

    const config = buildDestinationConfig(form);

    try {
      await saveDestination({
        destination_config_id: form.destination_config_id?.value || undefined,
        name: form.elements.name?.value || "",
        destination_type: form.destination_type.value,
        config_json: JSON.stringify(config),
        is_enabled: Boolean(form.is_enabled.checked),
        is_default: Boolean(form.is_default.checked),
      });
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_saved"), "success");
    } catch (err) {
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  return false;
}
