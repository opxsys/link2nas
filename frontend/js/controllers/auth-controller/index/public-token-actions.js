import { state } from "../../../state.js";
import { showAppMessage } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { acceptInvitation, confirmPasswordReset } from "../../../api.js";
import { renderLoginForm } from "../../../render/auth.js";
import { validatePasswordConfirmation } from "../validation.js";

export function bindPublicTokenAuthEvents({ bindAuthEvents, clearPublicAccountUrl }) {
  document.getElementById("accept-invitation-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const password = validatePasswordConfirmation(form);
    if (!password) return;

    try {
      await acceptInvitation(form.token.value, password);

      clearPublicAccountUrl();
      showAppMessage(t("messages.account_activated"), "success");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });

  document.getElementById("password-reset-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const password = validatePasswordConfirmation(form);
    if (!password) return;

    try {
      await confirmPasswordReset(form.token.value, password);

      clearPublicAccountUrl();
      showAppMessage(t("messages.password_reset_done"), "success");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("auth.error.password_reset_failed"), "error");
    }
  });

  document.getElementById("back-to-login-btn")?.addEventListener("click", () => {
    clearPublicAccountUrl();
    renderLoginForm(state.appInfo?.email_sending_available ?? true);
    bindAuthEvents();
  });
}
