import { state } from "../../../state.js";
import { showAppMessage } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import {
  acceptInvitation,
  confirmPasswordReset,
  changeMyPassword,
  getMe,
} from "../../../api.js";
import { bindSetupAuthEvents } from "./setup-actions.js";
import { bindLoginAuthEvents } from "./login-actions.js";
import { bindMagicLoginAuthEvents } from "./magic-login-actions.js";
import { renderLoginForm } from "../../../render/auth.js";
import { validatePasswordConfirmation, validateForcedPasswordChangeForm } from "../validation.js";
export { validatePasswordConfirmation, validateForcedPasswordChangeForm } from "../validation.js";

let _enterMainApplication;
let _hideAdminIfNeeded;
let _updateAuthVisibility;
let _clearPublicAccountUrl;
let _applyCurrentUserTheme;

export function initAuth({
  enterMainApplication,
  hideAdminIfNeeded,
  updateAuthVisibility,
  clearPublicAccountUrl,
  applyCurrentUserTheme,
}) {
  _enterMainApplication = enterMainApplication;
  _hideAdminIfNeeded = hideAdminIfNeeded;
  _updateAuthVisibility = updateAuthVisibility;
  _clearPublicAccountUrl = clearPublicAccountUrl;
  _applyCurrentUserTheme = applyCurrentUserTheme;
}

export function bindAuthEvents() {
  bindSetupAuthEvents({ bindAuthEvents });
  bindLoginAuthEvents({
    applyCurrentUserTheme: _applyCurrentUserTheme,
    updateAuthVisibility: _updateAuthVisibility,
    hideAdminIfNeeded: _hideAdminIfNeeded,
    enterMainApplication: _enterMainApplication,
    bindAuthEvents,
  });

  bindMagicLoginAuthEvents({ bindAuthEvents });

  document.getElementById("accept-invitation-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const password = validatePasswordConfirmation(form);
    if (!password) return;

    try {
      await acceptInvitation(form.token.value, password);

      _clearPublicAccountUrl();
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

      _clearPublicAccountUrl();
      showAppMessage(t("messages.password_reset_done"), "success");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("auth.error.password_reset_failed"), "error");
    }
  });

  document.getElementById("back-to-login-btn")?.addEventListener("click", () => {
    _clearPublicAccountUrl();
    renderLoginForm(state.appInfo?.email_sending_available ?? true);
    bindAuthEvents();
  });

  document.getElementById("forced-password-change-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const payload = validateForcedPasswordChangeForm(form);
    if (!payload) return;

    try {
      await changeMyPassword(payload);

      const me = await getMe();
      state.currentUser = me;
      _applyCurrentUserTheme(me);
      _updateAuthVisibility();

      if (me.force_password_change) {
        showAppMessage(t("auth.error.password_change_not_finalized"), "error");
        return;
      }

      _hideAdminIfNeeded();

      showAppMessage(t("messages.settings_password_changed"), "success");
      await _enterMainApplication({ useHomePage: true });

    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });
}
