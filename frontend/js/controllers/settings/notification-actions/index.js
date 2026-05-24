import { state } from "../../../state.js";
import { t } from "../../../i18n/index.js";
import {
  testNotificationConfig,
  testStoredNotificationConfig,
  updateNotificationConfig,
  deleteNotificationConfig,
  updateNotificationRule,
  deleteNotificationRule,
} from "../../../api.js";
import {
  fillNotificationChannelForm,
  resetNotificationChannelForm,
  fillNotificationRuleForm,
  resetNotificationRuleForm,
} from "../../../render/settings.js";
import { showConfirmModal } from "../../../ui/modals.js";
import { showNotificationFeedback } from "../feedback.js";
import { buildNotificationChannelPayload } from "../payloads.js";
import { loadSettings } from "../loader.js";

export async function handleNotificationAction(action, button) {
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
