import { createFirstAdmin } from "../../../api.js";
import { state } from "../../../state.js";
import { showAppMessage } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { renderLoginForm } from "../../../render/auth.js";

export function bindSetupAuthEvents({ bindAuthEvents }) {
  document.getElementById("setup-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;

    try {
      await createFirstAdmin({
        email: form.email.value,
        display_name: form.display_name.value,
        password: form.password.value,
      });

      showAppMessage(t("messages.super_admin_created"), "success");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });
}
