import { t } from "../../i18n/index.js";
import { revokeUserApiKey, deleteUserApiKey } from "../../api.js";
import { showConfirmModal } from "../../ui/modals.js";
import { showApiKeyFeedback } from "./feedback.js";
import { loadSettings } from "./loader.js";

export async function handleApiKeyAction(action, button) {
  if (action === "revoke-api-key") {
    const keyId = button.dataset.apiKeyId;

    if (!keyId) return true;

    const confirmed = await showConfirmModal({
      title: t("settings.api_keys.confirm_revoke_title"),
      message: t("settings.api_keys.confirm_revoke_message"),
      confirmLabel: t("settings.api_keys.revoke"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return true;

    try {
      await revokeUserApiKey(keyId);
      await loadSettings();
      showApiKeyFeedback(t("messages.settings_api_key_revoked"), "success");
    } catch (error) {
      showApiKeyFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "delete-api-key") {
    const keyId = button.dataset.apiKeyId;

    if (!keyId) return true;

    const confirmed = await showConfirmModal({
      title: t("settings.api_keys.confirm_delete_title"),
      message: t("settings.api_keys.confirm_delete_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return true;

    try {
      await deleteUserApiKey(keyId);
      await loadSettings();
      showApiKeyFeedback(t("messages.settings_api_key_deleted"), "success");
    } catch (error) {
      showApiKeyFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  return false;
}
