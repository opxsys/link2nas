import { t } from "../../i18n/index.js";
import { createUserApiKey } from "../../api.js";
import { showSecretModal } from "../../ui/modals.js";
import { showApiKeyFeedback } from "./feedback.js";
import { loadSettings } from "./loader.js";

export async function handleApiKeySubmit(form) {
  if (form.id === "api-key-form") {
    const scopes = Array.from(form.querySelectorAll("input[name='scope']:checked"))
      .map((input) => input.value)
      .filter(Boolean);

    try {
      const result = await createUserApiKey({
        name: form.name.value,
        scopes,
      });

      form.reset();

      await showSecretModal({
        title: t("settings.api_keys.modal_title"),
        message: t("settings.api_keys.modal_message"),
        secret: result.key,
        copyLabel: t("settings.api_keys.modal_copy"),
        closeLabel: t("common.close"),
      });
      await loadSettings();
    } catch (error) {
      showApiKeyFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  return false;
}
