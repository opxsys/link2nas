import { state } from "../../../state.js";
import { t } from "../../../i18n/index.js";
import {
  updateNotificationConfig,
  updateNotificationRule,
} from "../../../api.js";
import { showNotificationFeedback } from "../feedback.js";
import { loadSettings } from "../loader.js";

export async function handleNotificationToggleAction(action, button) {
  if (action === "toggle-notification-channel-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const cfg = state.notificationConfigs.find((c) => c.id === button.dataset.notificationConfigId);
    if (!cfg) { button.disabled = false; return true; }
    try {
      await updateNotificationConfig(cfg.id, {
        is_enabled: newEnabled,
        is_default: newEnabled ? cfg.is_default : false,
      });
      await loadSettings();
      showNotificationFeedback(t("messages.settings_channel_enabled_updated"), "success");
    } catch (error) {
      await loadSettings();
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "set-notification-channel-default") {
    if (!button.checked) { button.checked = true; return true; }
    button.disabled = true;
    const cfg = state.notificationConfigs.find((c) => c.id === button.dataset.notificationConfigId);
    if (!cfg) { button.disabled = false; return true; }
    try {
      await updateNotificationConfig(cfg.id, { is_enabled: true, is_default: true });
      await loadSettings();
      showNotificationFeedback(t("messages.settings_channel_default_updated"), "success");
    } catch (error) {
      await loadSettings();
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "toggle-notification-rule-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const rule = state.notificationRules.find((r) => r.id === button.dataset.notificationRuleId);
    if (!rule) { button.disabled = false; return true; }
    try {
      await updateNotificationRule(rule.id, { is_enabled: newEnabled });
      await loadSettings();
      showNotificationFeedback(t("messages.settings_rule_enabled_updated"), "success");
    } catch (error) {
      await loadSettings();
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  return false;
}
