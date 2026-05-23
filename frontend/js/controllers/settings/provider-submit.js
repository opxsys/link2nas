import { t } from "../../i18n/index.js";
import { saveProvider } from "../../api.js";
import { showProviderFeedback } from "./feedback.js";
import { loadSettings } from "./loader.js";

export async function handleProviderSubmit(form) {
  if (form.id === "provider-form") {
    try {
      await saveProvider({
        provider_config_id: form.provider_config_id?.value || undefined,
        name: form.elements.name?.value || "",
        provider_type: form.provider_type.value,
        api_key: form.api_key.value || undefined,
        is_enabled: Boolean(form.is_enabled.checked),
        is_default: Boolean(form.is_default.checked),
      });

      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_saved"), "success");
    } catch (error) {
      showProviderFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  return false;
}
