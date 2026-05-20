import { state } from "../state.js";
import { showAppMessage } from "../utils.js";
import { t } from "../i18n/index.js";
import { requestEmailVerification, testNotificationConfig } from "../api.js";
import { updateDestinationFields, updateNotificationChannelFields } from "../render/settings.js";
import { handleSettingsSubmit, handleSettingsClick } from "../controllers/settings-controller.js";

export function bindSettingsEvents() {
  document.getElementById("settings-page")?.addEventListener("change", (event) => {
    if (event.target?.id === "destination-name") {
      updateDestinationFields();
      return;
    }

    if (event.target?.id === "notification-channel") {
      updateNotificationChannelFields();
      return;
    }
  });

  document.getElementById("settings-page")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    try {
      await handleSettingsSubmit(event.target);
    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });

  document.getElementById("settings-page")?.addEventListener("click", async (event) => {
    const requestButton = event.target.closest("#request-email-verification-btn");
    if (requestButton) {
      if (!state.currentUser?.email_sending_available) {
        showAppMessage(t("email.smtp_configure_hint"), "error");
        return;
      }

      requestButton.disabled = true;

      try {
        const result = await requestEmailVerification();
        showAppMessage(result.message || t("messages.email_verification_sent"), "success");
      } catch (error) {
        showAppMessage(error.message || t("messages.email_verification_error"), "error");
      } finally {
        requestButton.disabled = false;
      }

      return;
    }

    const testEmailButton = event.target.closest("#test-email-notification-btn");
    if (testEmailButton) {
      try {
        const result = await testNotificationConfig({
          channel: "email",
          config: {},
        });

        showAppMessage(result.message || t("messages.settings_channel_test_ok"), "success");
      } catch (error) {
        showAppMessage(error.message || t("messages.settings_action_error"), "error");
      }
      return;
    }

    const button = event.target.closest("[data-settings-action], [data-action]");
    if (!button) return;

    try {
      await handleSettingsClick(button);
    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });
}
