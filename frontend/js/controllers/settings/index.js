import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import {
  saveProvider,
  deleteProvider,
  testProvider,
  saveDestination,
  deleteDestination,
  testDestination,
  testProviderFromSettings,
  testDestinationFromSettings,
  testNotificationConfig,
  testStoredNotificationConfig,
  createNotificationConfig,
  updateNotificationConfig,
  deleteNotificationConfig,
  createNotificationRule,
  updateNotificationRule,
  deleteNotificationRule,
  createUserApiKey,
  revokeUserApiKey,
  deleteUserApiKey,
} from "../../api.js";
import {
  fillProviderForm,
  fillDestinationForm,
  updateDestinationFields,
  fillNotificationChannelForm,
  resetNotificationChannelForm,
  fillNotificationRuleForm,
  resetNotificationRuleForm,
} from "../../render/settings.js";
import { showAppMessage } from "../../utils.js";
import { showConfirmModal, showSecretModal } from "../../ui/modals.js";
import {
  showApiKeyFeedback,
  showProviderFeedback,
  showDestinationFeedback,
  showNotificationFeedback,
} from "./feedback.js";
import {
  buildDestinationConfigJsonFromState,
  buildDestinationConfig,
  buildNotificationChannelPayload,
  buildNotificationRulePayload,
} from "./payloads.js";
import { loadSettings, onSettingsTabChange } from "./loader.js";
export { loadSettings, onSettingsTabChange };
export { loadEspace } from "./espace.js";
import { handleAccountSubmit } from "./account-submit.js";
import { handleProwlarrSubmit } from "./prowlarr-submit.js";
import { handleProviderSubmit } from "./provider-submit.js";
import { handleDestinationSubmit } from "./destination-submit.js";

export async function handleSettingsSubmit(form) {
  if (await handleAccountSubmit(form)) return;
  if (await handleProwlarrSubmit(form)) return;
  if (await handleProviderSubmit(form)) return;
  if (await handleDestinationSubmit(form)) return;

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
    return;
  }

  if (form.id === "test-gotify-form") {
    const result = await testNotificationConfig({
      channel: "gotify",
      config: {
        server_url: form.server_url.value,
        token: form.token.value,
      },
    });

    showAppMessage(result.message || t("messages.settings_channel_test_ok"), "success");
    return;
  }

  if (form.id === "test-webhook-form") {
    const result = await testNotificationConfig({
      channel: "webhook",
      config: {
        url: form.url.value,
        method: "POST",
      },
    });

    showAppMessage(result.message || t("messages.settings_channel_test_ok"), "success");
    return;
  }

  if (form.id === "notification-channel-form") {
    const configId = String(form.config_id?.value || "").trim();
    const payload = buildNotificationChannelPayload(form);

    try {
      if (configId) {
        await updateNotificationConfig(configId, payload);
        await loadSettings();
        showNotificationFeedback(t("messages.settings_channel_updated"), "success");
      } else {
        await createNotificationConfig(payload);
        await loadSettings();
        showNotificationFeedback(t("messages.settings_channel_created"), "success");
      }
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (form.id === "notification-rule-form") {
    const ruleId = String(form.rule_id?.value || "").trim();
    const payload = buildNotificationRulePayload(form);

    if (!payload.config_id) {
      showNotificationFeedback(t("messages.select_notification_channel"), "error");
      return;
    }

    try {
      if (ruleId) {
        await updateNotificationRule(ruleId, payload);
        await loadSettings();
        showNotificationFeedback(t("messages.settings_rule_updated"), "success");
      } else {
        await createNotificationRule(payload);
        await loadSettings();
        showNotificationFeedback(t("messages.settings_rule_created"), "success");
      }
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }
}

export async function handleSettingsClick(button) {
  const action = button.dataset.settingsAction || button.dataset.action;

  if (action === "edit-provider") {
    const provider = state.providers.find((p) => p.id === button.dataset.providerId);
    fillProviderForm(provider);
    return;
  }

  if (action === "cancel-provider-edit") {
    const form = document.getElementById("provider-form");
    if (!form) return;
    form.reset();
    form.provider_config_id.value = "";
    form.querySelector("button[type='submit']").textContent = t("settings.providers.save");
    button.hidden = true;
    return;
  }

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

  if (action === "toggle-provider-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const payload = {
      provider_config_id: button.dataset.providerId,
      provider_type: button.dataset.providerType,
      name: button.dataset.providerName,
      is_enabled: newEnabled,
      is_default: newEnabled ? button.dataset.isDefault === "1" : false,
    };
    try {
      await saveProvider(payload);
      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_enabled_updated"), "success");
    } catch (err) {
      await loadSettings();
      showProviderFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "set-provider-default") {
    if (!button.checked) {
      button.checked = true;
      return;
    }
    button.disabled = true;
    const payload = {
      provider_config_id: button.dataset.providerId,
      provider_type: button.dataset.providerType,
      name: button.dataset.providerName,
      is_enabled: true,
      is_default: true,
    };
    try {
      await saveProvider(payload);
      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_default_updated"), "success");
    } catch (err) {
      await loadSettings();
      showProviderFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "test-provider") {
    const providerId = button.dataset.providerId;
    try {
      const result = await testProvider(providerId);
      await loadSettings();
      const name = result.provider_user?.username || t("messages.settings_provider_tested_ok");
      showProviderFeedback(`${t("messages.settings_provider_tested")}: ${name}`, "success");
    } catch (error) {
      showProviderFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "delete-provider") {
    try {
      await deleteProvider(button.dataset.providerId);
      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_deleted"), "success");
    } catch (error) {
      showProviderFeedback(error.message || t("messages.settings_action_error"), "error");
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

  if (action === "test-provider-settings") {
    const result = await testProviderFromSettings(button.dataset.providerId);
    showAppMessage(
      `Provider OK: ${result.provider_user?.username || "compte valide"}`,
      "success"
    );
    await loadSettings();
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

  if (action === "revoke-api-key") {
    const keyId = button.dataset.apiKeyId;

    if (!keyId) return;

    const confirmed = await showConfirmModal({
      title: t("settings.api_keys.confirm_revoke_title"),
      message: t("settings.api_keys.confirm_revoke_message"),
      confirmLabel: t("settings.api_keys.revoke"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await revokeUserApiKey(keyId);
      await loadSettings();
      showApiKeyFeedback(t("messages.settings_api_key_revoked"), "success");
    } catch (error) {
      showApiKeyFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "delete-api-key") {
    const keyId = button.dataset.apiKeyId;

    if (!keyId) return;

    const confirmed = await showConfirmModal({
      title: t("settings.api_keys.confirm_delete_title"),
      message: t("settings.api_keys.confirm_delete_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await deleteUserApiKey(keyId);
      await loadSettings();
      showApiKeyFeedback(t("messages.settings_api_key_deleted"), "success");
    } catch (error) {
      showApiKeyFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

}
