import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { saveProvider, deleteProvider, testProvider, testProviderFromSettings } from "../../api.js";
import { fillProviderForm } from "../../render/settings.js";
import { showAppMessage } from "../../utils.js";
import { showProviderFeedback } from "./feedback.js";
import { loadSettings } from "./loader.js";

export async function handleProviderAction(action, button) {
  if (action === "edit-provider") {
    const provider = state.providers.find((p) => p.id === button.dataset.providerId);
    fillProviderForm(provider);
    return true;
  }

  if (action === "cancel-provider-edit") {
    const form = document.getElementById("provider-form");
    if (!form) return true;
    form.reset();
    form.provider_config_id.value = "";
    form.querySelector("button[type='submit']").textContent = t("settings.providers.save");
    button.hidden = true;
    return true;
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
    return true;
  }

  if (action === "set-provider-default") {
    if (!button.checked) {
      button.checked = true;
      return true;
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
    return true;
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
    return true;
  }

  if (action === "delete-provider") {
    try {
      await deleteProvider(button.dataset.providerId);
      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_deleted"), "success");
    } catch (error) {
      showProviderFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return true;
  }

  if (action === "test-provider-settings") {
    const result = await testProviderFromSettings(button.dataset.providerId);
    showAppMessage(
      `Provider OK: ${result.provider_user?.username || "compte valide"}`,
      "success"
    );
    await loadSettings();
    return true;
  }

  return false;
}
