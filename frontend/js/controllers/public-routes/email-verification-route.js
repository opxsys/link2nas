import { getToken, clearToken } from "../../core/session.js";
import { state } from "../../state.js";
import { showAppMessage } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { confirmEmailVerification, getMe } from "../../api.js";
import {
  renderInvalidToken,
  renderEmailVerificationProcessing,
  renderLoginForm,
} from "../../render/auth.js";
import { bindAuthEvents } from "../auth-controller.js";
import { isEmailVerificationRoute } from "./route-utils.js";

export async function handleEmailVerificationRoute({
  token,
  updateAuthVisibility,
  enterMainApplication,
  applyCurrentUserTheme,
  clearPublicAccountUrl,
}) {
  if (!isEmailVerificationRoute()) {
    return false;
  }

  renderEmailVerificationProcessing();

  try {
    await confirmEmailVerification(token);

    clearPublicAccountUrl();
    showAppMessage(t("messages.email_validated"), "success");

    const existingToken = getToken();
    if (existingToken) {
      try {
        state.currentUser = await getMe();
        applyCurrentUserTheme(state.currentUser);
        updateAuthVisibility();
        await enterMainApplication();
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
