import { state } from "../../../state.js";
import { showAppMessage } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import {
  changeMyPassword,
  getMe,
} from "../../../api.js";
import { bindSetupAuthEvents } from "./setup-actions.js";
import { bindLoginAuthEvents } from "./login-actions.js";
import { bindMagicLoginAuthEvents } from "./magic-login-actions.js";
import { bindPublicTokenAuthEvents } from "./public-token-actions.js";
import { validateForcedPasswordChangeForm } from "../validation.js";
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
  bindPublicTokenAuthEvents({
    bindAuthEvents,
    clearPublicAccountUrl: _clearPublicAccountUrl,
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
