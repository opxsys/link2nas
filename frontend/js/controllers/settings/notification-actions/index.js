import { t } from "../../../i18n/index.js";
import {
  testNotificationConfig,
  testStoredNotificationConfig,
} from "../../../api.js";
import { showNotificationFeedback } from "../feedback.js";
import { buildNotificationChannelPayload } from "../payloads.js";
import { handleNotificationFormAction } from "./form-actions.js";
import { handleNotificationToggleAction } from "./toggle-actions.js";
import { handleNotificationDeleteAction } from "./delete-actions.js";

export async function handleNotificationAction(action, button) {
  if (handleNotificationFormAction(action, button)) return true;
  if (await handleNotificationToggleAction(action, button)) return true;
  if (await handleNotificationDeleteAction(action, button)) return true;

  if (action === "test-stored-notification-channel") {
    const configId = button.dataset.notificationConfigId;

    if (!configId) return true;

    try {
      const result = await testStoredNotificationConfig(configId);
      showNotificationFeedback(result.message || t("messages.settings_channel_test_ok"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "test-notification-channel-form") {
    const form = document.getElementById("notification-channel-form");
    if (!form) return true;

    const payload = buildNotificationChannelPayload(form);

    try {
      const result = await testNotificationConfig({
        channel: payload.channel,
        name: payload.name,
        config: payload.config,
      });
      showNotificationFeedback(result.message || t("messages.settings_channel_test_ok"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  return false;
}
