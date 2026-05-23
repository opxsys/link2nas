import { t } from "../../i18n/index.js";
import {
  testNotificationConfig,
  createNotificationConfig,
  updateNotificationConfig,
  createNotificationRule,
  updateNotificationRule,
} from "../../api.js";
import { showAppMessage } from "../../utils.js";
import { showNotificationFeedback } from "./feedback.js";
import { buildNotificationChannelPayload, buildNotificationRulePayload } from "./payloads.js";
import { loadSettings } from "./loader.js";

export async function handleNotificationSubmit(form) {
  if (form.id === "test-gotify-form") {
    const result = await testNotificationConfig({
      channel: "gotify",
      config: {
        server_url: form.server_url.value,
        token: form.token.value,
      },
    });

    showAppMessage(result.message || t("messages.settings_channel_test_ok"), "success");
    return true;
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
    return true;
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
    return true;
  }

  if (form.id === "notification-rule-form") {
    const ruleId = String(form.rule_id?.value || "").trim();
    const payload = buildNotificationRulePayload(form);

    if (!payload.config_id) {
      showNotificationFeedback(t("messages.select_notification_channel"), "error");
      return true;
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
    return true;
  }

  return false;
}
