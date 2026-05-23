import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { updateMe, changeMyPassword } from "../../api.js";
import { showAppMessage } from "../../utils.js";
import { applyCurrentUserTheme } from "../../core/theme.js";
import { loadSettings } from "./loader.js";

export async function handleAccountSubmit(form) {
  if (form.id === "my-profile-form") {
    const previousEmail = String(state.currentUser?.email || "").trim().toLowerCase();
    const newEmail = String(form.email.value || "").trim().toLowerCase();

    const me = await updateMe({
      email: form.email.value,
      display_name: form.display_name.value,
      preferred_language: form.preferred_language.value,
      receive_application_emails: Boolean(form.receive_application_emails?.checked),
      ui_theme: form.ui_theme?.value || "auto",
    });

    state.currentUser = me;
    applyCurrentUserTheme(me);

    if (newEmail && previousEmail && newEmail !== previousEmail) {
      showAppMessage(
        t("messages.settings_profile_updated_email"),
        "info"
      );
    } else {
      showAppMessage(t("messages.settings_profile_updated"), "success");
    }

    await loadSettings();
    return true;
  }

  if (form.id === "change-password-form") {
    await changeMyPassword({
      current_password: form.current_password.value,
      new_password: form.new_password.value,
    });

    form.reset();
    showAppMessage(t("messages.settings_password_changed"), "success");
    return true;
  }

  return false;
}
