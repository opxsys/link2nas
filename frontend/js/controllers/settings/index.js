import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import {
  saveDestination,
  deleteDestination,
  testDestination,
  testDestinationFromSettings,
  testNotificationConfig,
  testStoredNotificationConfig,
  updateNotificationConfig,
  deleteNotificationConfig,
  updateNotificationRule,
  deleteNotificationRule,
} from "../../api.js";
import {
  fillDestinationForm,
  updateDestinationFields,
  fillNotificationChannelForm,
  resetNotificationChannelForm,
  fillNotificationRuleForm,
  resetNotificationRuleForm,
} from "../../render/settings.js";
import { showAppMessage } from "../../utils.js";
import { showConfirmModal } from "../../ui/modals.js";
import {
  showApiKeyFeedback,
  showDestinationFeedback,
  showNotificationFeedback,
} from "./feedback.js";
import {
  buildDestinationConfigJsonFromState,
  buildDestinationConfig,
  buildNotificationChannelPayload,
} from "./payloads.js";
import { loadSettings, onSettingsTabChange } from "./loader.js";
export { loadSettings, onSettingsTabChange };
export { loadEspace } from "./espace.js";
import { handleAccountSubmit } from "./account-submit.js";
import { handleProwlarrSubmit } from "./prowlarr-submit.js";
import { handleProviderSubmit } from "./provider-submit.js";
import { handleDestinationSubmit } from "./destination-submit.js";
import { handleApiKeySubmit } from "./api-key-submit.js";
import { handleNotificationSubmit } from "./notification-submit.js";
import { handleApiKeyAction } from "./api-key-actions.js";
import { handleProviderAction } from "./provider-actions.js";

export async function handleSettingsSubmit(form) {
  if (await handleAccountSubmit(form)) return;
  if (await handleProwlarrSubmit(form)) return;
  if (await handleProviderSubmit(form)) return;
  if (await handleDestinationSubmit(form)) return;
  if (await handleApiKeySubmit(form)) return;
  if (await handleNotificationSubmit(form)) return;
}

export async function handleSettingsClick(button) {
  const action = button.dataset.settingsAction || button.dataset.action;
  if (await handleApiKeyAction(action, button)) return;
  if (await handleProviderAction(action, button)) return;

  if (action === "toggle-destination-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const dest = state.destinations.find((d) => d.id === button.dataset.destinationId);
    if (!dest) { button.disabled = false; return; }
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
    return;
  }

  if (action === "set-destination-default") {
    if (!button.checked) { button.checked = true; return; }
    button.disabled = true;
    const dest = state.destinations.find((d) => d.id === button.dataset.destinationId);
    if (!dest) { button.disabled = false; return; }
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
    return;
  }

  if (action === "cancel-destination-edit") {
    const form = document.getElementById("destination-form");
    if (!form) return;
    form.reset();
    form.destination_config_id.value = "";
    form.querySelector("button[type='submit']").textContent = t("settings.destinations.save");
    button.hidden = true;
    updateDestinationFields();
    return;
  }

  if (action === "edit-destination") {
    const destination = state.destinations.find((d) => d.id === button.dataset.destinationId);
    fillDestinationForm(destination);
    return;
  }

  if (action === "test-destination") {
    try {
      const result = await testDestination(button.dataset.destinationId);
      await loadSettings();
      showDestinationFeedback(result.message || t("messages.settings_destination_tested"), "success");
    } catch (err) {
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "delete-destination") {
    try {
      await deleteDestination(button.dataset.destinationId);
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_deleted"), "success");
    } catch (err) {
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "test-destination-settings") {
    const result = await testDestinationFromSettings(button.dataset.destinationId);
    showAppMessage(result.message || t("messages.settings_destination_tested"), "success");
    return;
  }

  if (action === "reset-notification-channel-form") {
    resetNotificationChannelForm();
    return;
  }

  if (action === "reset-notification-rule-form") {
    resetNotificationRuleForm();
    return;
  }

  if (action === "show-prowlarr-api-key-modal") {
    const confirmed = await showConfirmModal({
      title: t("settings.prowlarr.no_qbt_key_modal_title"),
      message: t("settings.prowlarr.no_qbt_key_modal_message"),
      confirmLabel: t("settings.prowlarr.no_qbt_key_modal_goto"),
      cancelLabel: t("common.close"),
      danger: false,
    });
    if (confirmed) {
      document.querySelector('[data-settings-tab="api_keys"]')?.click();
    }
    return;
  }

  if (action === "cancel-notification-channel-edit") {
    resetNotificationChannelForm();
    button.hidden = true;
    return;
  }

  if (action === "cancel-notification-rule-edit") {
    resetNotificationRuleForm();
    button.hidden = true;
    return;
  }

  if (action === "toggle-notification-channel-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const cfg = state.notificationConfigs.find((c) => c.id === button.dataset.notificationConfigId);
    if (!cfg) { button.disabled = false; return; }
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
    return;
  }

  if (action === "set-notification-channel-default") {
    if (!button.checked) { button.checked = true; return; }
    button.disabled = true;
    const cfg = state.notificationConfigs.find((c) => c.id === button.dataset.notificationConfigId);
    if (!cfg) { button.disabled = false; return; }
    try {
      await updateNotificationConfig(cfg.id, { is_enabled: true, is_default: true });
      await loadSettings();
      showNotificationFeedback(t("messages.settings_channel_default_updated"), "success");
    } catch (error) {
      await loadSettings();
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "toggle-notification-rule-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const rule = state.notificationRules.find((r) => r.id === button.dataset.notificationRuleId);
    if (!rule) { button.disabled = false; return; }
    try {
      await updateNotificationRule(rule.id, { is_enabled: newEnabled });
      await loadSettings();
      showNotificationFeedback(t("messages.settings_rule_enabled_updated"), "success");
    } catch (error) {
      await loadSettings();
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "edit-notification-channel") {
    const configId = button.dataset.notificationConfigId;
    const config = state.notificationConfigs.find((item) => item.id === configId);

    if (!config) {
      showNotificationFeedback(t("messages.settings_channel_not_found"), "error");
      return;
    }

    fillNotificationChannelForm(config);
    return;
  }

  if (action === "test-stored-notification-channel") {
    const configId = button.dataset.notificationConfigId;

    if (!configId) return;

    try {
      const result = await testStoredNotificationConfig(configId);
      showNotificationFeedback(result.message || t("messages.settings_channel_test_ok"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "delete-notification-channel") {
    const configId = button.dataset.notificationConfigId;

    if (!configId) return;

    const confirmed = await showConfirmModal({
      title: t("settings.notifications.confirm_delete_channel_title"),
      message: t("settings.notifications.confirm_delete_channel_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await deleteNotificationConfig(configId);
      await loadSettings();
      showNotificationFeedback(t("messages.settings_channel_deleted"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "edit-notification-rule") {
    const ruleId = button.dataset.notificationRuleId;
    const rule = state.notificationRules.find((item) => item.id === ruleId);

    if (!rule) {
      showNotificationFeedback(t("messages.settings_rule_not_found"), "error");
      return;
    }

    fillNotificationRuleForm(rule);
    return;
  }

  if (action === "delete-notification-rule") {
    const ruleId = button.dataset.notificationRuleId;

    if (!ruleId) return;

    const confirmed = await showConfirmModal({
      title: t("settings.notifications.confirm_delete_rule_title"),
      message: t("settings.notifications.confirm_delete_rule_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await deleteNotificationRule(ruleId);
      await loadSettings();
      showNotificationFeedback(t("messages.settings_rule_deleted"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "test-notification-channel-form") {
    const form = document.getElementById("notification-channel-form");
    if (!form) return;

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
    return;
  }

}
