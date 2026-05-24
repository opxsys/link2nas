import { setToken } from "../../../core/session.js";
import { state } from "../../../state.js";
import { showAppMessage } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { login } from "../../../api.js";
import { renderForcedPasswordChangeForm } from "../../../render/auth.js";

export function bindLoginAuthEvents({
  applyCurrentUserTheme,
  updateAuthVisibility,
  hideAdminIfNeeded,
  enterMainApplication,
  bindAuthEvents,
}) {
  document.getElementById("login-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;

    try {
      const result = await login({
        email: form.email.value,
        password: form.password.value,
      });

      setToken(result.token);
      state.currentUser = result.user;
      applyCurrentUserTheme(result.user);
      updateAuthVisibility();

      if (result.user?.force_password_change) {
        renderForcedPasswordChangeForm();
        bindAuthEvents();
        showAppMessage(t("messages.must_change_password"), "info");
        return;
      }

      hideAdminIfNeeded();

      await enterMainApplication({ useHomePage: true });
    } catch (error) {
      showAppMessage(error.message || t("auth.error.invalid_credentials"), "error");
    }
  });
}
