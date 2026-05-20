import { getToken, setToken, clearToken } from "../core/session.js";
import { state } from "../state.js";
import { showAppMessage } from "../utils.js";
import { t } from "../i18n/index.js";
import {
  getPublicTokenStatus,
  confirmMagicLogin,
  confirmEmailVerification,
  getMe,
} from "../api.js";
import {
  renderInvalidToken,
  renderAcceptInvitationForm,
  renderPasswordResetForm,
  renderForcedPasswordChangeForm,
  renderMagicLoginProcessing,
  renderEmailVerificationProcessing,
  renderLoginForm,
} from "../render/auth.js";
import { bindAuthEvents } from "./auth-controller.js";

let _updateAuthVisibility;
let _enterMainApplication;
let _hideAdminIfNeeded;
let _applyCurrentUserTheme;

export function initPublicRoutes({
  updateAuthVisibility,
  enterMainApplication,
  hideAdminIfNeeded,
  applyCurrentUserTheme,
}) {
  _updateAuthVisibility = updateAuthVisibility;
  _enterMainApplication = enterMainApplication;
  _hideAdminIfNeeded = hideAdminIfNeeded;
  _applyCurrentUserTheme = applyCurrentUserTheme;
}

function getPublicTokenFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return String(params.get("token") || "").trim();
}

function isInviteRoute() {
  return window.location.pathname === "/invite";
}

function isPasswordResetRoute() {
  return window.location.pathname === "/reset-password";
}

function isMagicLoginRoute() {
  return window.location.pathname === "/magic-login";
}

function isEmailVerificationRoute() {
  return window.location.pathname === "/verify-email";
}

export function clearPublicAccountUrl() {
  window.history.replaceState({}, "", "/");
}

export async function handlePublicAccountRoute() {
  if (
    !isInviteRoute() &&
    !isPasswordResetRoute() &&
    !isMagicLoginRoute() &&
    !isEmailVerificationRoute()
  ) {
    return false;
  }

  clearToken();
  state.currentUser = null;
  _updateAuthVisibility();

  const token = getPublicTokenFromUrl();

  if (!token) {
    renderInvalidToken(t("auth.error.token_missing"));
    bindAuthEvents();
    return true;
  }

  try {
    const tokenStatus = await getPublicTokenStatus(token);

    if (isInviteRoute()) {
      if (tokenStatus.token_type !== "invitation") {
        renderInvalidToken(t("auth.error.not_invitation_link"));
        bindAuthEvents();
        return true;
      }

      renderAcceptInvitationForm(token, tokenStatus);
      bindAuthEvents();
      return true;
    }

    if (isPasswordResetRoute()) {
      if (tokenStatus.token_type !== "password_reset") {
        renderInvalidToken(t("auth.error.not_reset_link"));
        bindAuthEvents();
        return true;
      }

      renderPasswordResetForm(token, tokenStatus);
      bindAuthEvents();
      return true;
    }

    if (isMagicLoginRoute()) {
      renderMagicLoginProcessing();

      try {
        const result = await confirmMagicLogin(token);

        setToken(result.token);
        state.currentUser = result.user;
        _applyCurrentUserTheme(result.user);
        _updateAuthVisibility();

        clearPublicAccountUrl();

        if (result.user?.force_password_change) {
          renderForcedPasswordChangeForm();
          bindAuthEvents();
          showAppMessage(t("messages.must_change_password"), "info");
          return true;
        }

        _hideAdminIfNeeded();
        await _enterMainApplication({ useHomePage: true });

        return true;
      } catch (error) {
        renderInvalidToken(error.message || t("auth.error.magic_link_invalid"));
        bindAuthEvents();
        return true;
      }
    }

    if (isEmailVerificationRoute()) {
      renderEmailVerificationProcessing();

      try {
        await confirmEmailVerification(token);

        clearPublicAccountUrl();
        showAppMessage(t("messages.email_validated"), "success");

        const existingToken = getToken();
        if (existingToken) {
          try {
            state.currentUser = await getMe();
            _applyCurrentUserTheme(state.currentUser);
            _updateAuthVisibility();
            await _enterMainApplication();
            return true;
          } catch {
            clearToken();
          }
        }

        renderLoginForm(state.appInfo?.email_sending_available ?? true);
        bindAuthEvents();
        return true;
      } catch (error) {
        renderInvalidToken(error.message || t("auth.error.email_verification_invalid"));
        bindAuthEvents();
        return true;
      }
    }

  } catch (error) {
    renderInvalidToken(error.message || t("auth.invalid_token_message"));
    bindAuthEvents();
    return true;
  }

  return false;
}
