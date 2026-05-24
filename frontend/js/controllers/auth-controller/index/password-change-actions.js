import { state } from "../../../state.js";
import { showAppMessage } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { changeMyPassword, getMe } from "../../../api.js";
import { validateForcedPasswordChangeForm } from "../validation.js";

export function bindForcedPasswordChangeAuthEvents({
  applyCurrentUserTheme,
  updateAuthVisibility,
  hideAdminIfNeeded,
  enterMainApplication,
}) {
  document.getElementById("forced-password-change-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const payload = validateForcedPasswordChangeForm(form);
    if (!payload) return;

    try {
      await changeMyPassword(payload);

      const me = await getMe();
      state.currentUser = me;
      applyCurrentUserTheme(me);
      updateAuthVisibility();

      if (me.force_password_change) {
        showAppMessage(t("auth.error.password_change_not_finalized"), "error");
        return;
      }

      hideAdminIfNeeded();

      showAppMessage(t("messages.settings_password_changed"), "success");
      await enterMainApplication({ useHomePage: true });

    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });
}
