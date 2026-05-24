import { state } from "../../../state.js";
import { t } from "../../../i18n/index.js";
import {
  fillNotificationChannelForm,
  resetNotificationChannelForm,
  fillNotificationRuleForm,
  resetNotificationRuleForm,
} from "../../../render/settings.js";
import { showNotificationFeedback } from "../feedback.js";

export function handleNotificationFormAction(action, button) {
  if (action === "reset-notification-channel-form") {
    resetNotificationChannelForm();
    return true;
  }

  if (action === "reset-notification-rule-form") {
    resetNotificationRuleForm();
    return true;
  }

  if (action === "cancel-notification-channel-edit") {
    resetNotificationChannelForm();
    button.hidden = true;
    return true;
  }

  if (action === "cancel-notification-rule-edit") {
    resetNotificationRuleForm();
    button.hidden = true;
    return true;
  }

  if (action === "edit-notification-channel") {
    const configId = button.dataset.notificationConfigId;
    const config = state.notificationConfigs.find((item) => item.id === configId);

    if (!config) {
      showNotificationFeedback(t("messages.settings_channel_not_found"), "error");
      return true;
    }

    fillNotificationChannelForm(config);
    return true;
  }

  if (action === "edit-notification-rule") {
    const ruleId = button.dataset.notificationRuleId;
    const rule = state.notificationRules.find((item) => item.id === ruleId);

    if (!rule) {
      showNotificationFeedback(t("messages.settings_rule_not_found"), "error");
      return true;
    }

    fillNotificationRuleForm(rule);
    return true;
  }

  return false;
}
