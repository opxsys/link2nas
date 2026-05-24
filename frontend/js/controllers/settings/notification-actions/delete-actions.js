import { t } from "../../../i18n/index.js";
import {
  deleteNotificationConfig,
  deleteNotificationRule,
} from "../../../api.js";
import { showConfirmModal } from "../../../ui/modals.js";
import { showNotificationFeedback } from "../feedback.js";
import { loadSettings } from "../loader.js";

export async function handleNotificationDeleteAction(action, button) {
  if (action === "delete-notification-channel") {
    const configId = button.dataset.notificationConfigId;

    if (!configId) return true;

    const confirmed = await showConfirmModal({
      title: t("settings.notifications.confirm_delete_channel_title"),
      message: t("settings.notifications.confirm_delete_channel_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return true;

    try {
      await deleteNotificationConfig(configId);
      await loadSettings();
      showNotificationFeedback(t("messages.settings_channel_deleted"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "delete-notification-rule") {
    const ruleId = button.dataset.notificationRuleId;

    if (!ruleId) return true;

    const confirmed = await showConfirmModal({
      title: t("settings.notifications.confirm_delete_rule_title"),
      message: t("settings.notifications.confirm_delete_rule_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return true;

    try {
      await deleteNotificationRule(ruleId);
      await loadSettings();
      showNotificationFeedback(t("messages.settings_rule_deleted"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  return false;
}
