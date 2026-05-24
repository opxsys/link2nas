import { getToken, setToken, clearToken } from "../core/session.js";
import { state } from "../state.js";
import { showAppMessage } from "../utils.js";
import { t } from "../i18n/index.js";
import {
  getPublicTokenStatus,
  confirmEmailVerification,
  getMe,
} from "../api.js";
import {
  renderInvalidToken,
  renderEmailVerificationProcessing,
  renderLoginForm,
} from "../render/auth.js";
import { bindAuthEvents } from "./auth-controller.js";
import {
  getPublicTokenFromUrl,
  isEmailVerificationRoute,
  isPublicAccountRoute,
} from "./public-routes/route-utils.js";
import {
  handleInvitationRoute,
  handlePasswordResetRoute,
} from "./public-routes/invitation-reset-routes.js";
import { handleMagicLoginRoute } from "./public-routes/magic-login-route.js";

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

export function clearPublicAccountUrl() {
  window.history.replaceState({}, "", "/");
}

export async function handlePublicAccountRoute() {
  if (!isPublicAccountRoute()) {
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

    if (handleInvitationRoute({ token, tokenStatus })) return true;
    if (handlePasswordResetRoute({ token, tokenStatus })) return true;

    if (await handleMagicLoginRoute({
      token,
      setToken,
      state,
      applyCurrentUserTheme: _applyCurrentUserTheme,
      updateAuthVisibility: _updateAuthVisibility,
      clearPublicAccountUrl,
      hideAdminIfNeeded: _hideAdminIfNeeded,
      enterMainApplication: _enterMainApplication,
    })) return true;

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
