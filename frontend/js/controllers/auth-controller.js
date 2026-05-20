import { setToken } from "../core/session.js";
import { state } from "../state.js";
import { showAppMessage } from "../utils.js";
import { t } from "../i18n/index.js";
import {
  createFirstAdmin,
  login,
  requestMagicLogin,
  acceptInvitation,
  confirmPasswordReset,
  changeMyPassword,
  getMe,
} from "../api.js";
import {
  renderLoginForm,
  renderForcedPasswordChangeForm,
  renderMagicLoginRequestForm,
} from "../render/auth.js";

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

export function validatePasswordConfirmation(form) {
  const password = String(form.password?.value || "");
  const passwordConfirm = String(form.password_confirm?.value || "");

  if (password.length < 8) {
    showAppMessage(t("auth.error.password_too_short"), "error");
    return null;
  }

  if (password !== passwordConfirm) {
    showAppMessage(t("auth.error.passwords_mismatch"), "error");
    return null;
  }

  return password;
}

export function validateForcedPasswordChangeForm(form) {
  const currentPassword = String(form.current_password?.value || "");
  const newPassword = String(form.new_password?.value || "");
  const newPasswordConfirm = String(form.new_password_confirm?.value || "");

  if (!currentPassword) {
    showAppMessage(t("auth.error.temp_password_required"), "error");
    return null;
  }

  if (newPassword.length < 8) {
    showAppMessage(t("auth.error.new_password_too_short"), "error");
    return null;
  }

  if (newPassword !== newPasswordConfirm) {
    showAppMessage(t("auth.error.new_passwords_mismatch"), "error");
    return null;
  }

  if (currentPassword === newPassword) {
    showAppMessage(t("auth.error.new_password_same_as_temp"), "error");
    return null;
  }

  return {
    current_password: currentPassword,
    new_password: newPassword,
  };
}

export function bindAuthEvents() {
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
      _applyCurrentUserTheme(result.user);
      _updateAuthVisibility();

      if (result.user?.force_password_change) {
        renderForcedPasswordChangeForm();
        bindAuthEvents();
        showAppMessage(t("messages.must_change_password"), "info");
        return;
      }

      _hideAdminIfNeeded();

      await _enterMainApplication({ useHomePage: true });
    } catch (error) {
      showAppMessage(error.message || t("auth.error.invalid_credentials"), "error");
    }
  });

  document.getElementById("show-magic-login-btn")?.addEventListener("click", () => {
    renderMagicLoginRequestForm();
    bindAuthEvents();
  });

  document.getElementById("magic-login-request-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const email = String(form.email?.value || "").trim();

    if (!email) {
      showAppMessage(t("auth.error.email_required"), "error");
      return;
    }

    try {
      const result = await requestMagicLogin(email);
      showAppMessage(
        result.message || t("auth.magic_login_sent"),
        "success"
      );
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("auth.error.magic_login_send_failed"), "error");
    }
  });

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
