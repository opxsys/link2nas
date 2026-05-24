import { t } from "../../i18n/index.js";
import { confirmMagicLogin } from "../../api.js";
import {
  renderInvalidToken,
  renderForcedPasswordChangeForm,
  renderMagicLoginProcessing,
} from "../../render/auth.js";
import { showAppMessage } from "../../utils.js";
import { bindAuthEvents } from "../auth-controller.js";
import { isMagicLoginRoute } from "./route-utils.js";

export async function handleMagicLoginRoute({
  token,
  setToken,
  state,
  applyCurrentUserTheme,
  updateAuthVisibility,
  clearPublicAccountUrl,
  hideAdminIfNeeded,
  enterMainApplication,
}) {
  if (!isMagicLoginRoute()) {
    return false;
  }

  renderMagicLoginProcessing();

  try {
    const result = await confirmMagicLogin(token);

    setToken(result.token);
    state.currentUser = result.user;
    applyCurrentUserTheme(result.user);
    updateAuthVisibility();

    clearPublicAccountUrl();

    if (result.user?.force_password_change) {
      renderForcedPasswordChangeForm();
      bindAuthEvents();
      showAppMessage(t("messages.must_change_password"), "info");
      return true;
    }

    hideAdminIfNeeded();
    await enterMainApplication({ useHomePage: true });

    return true;
  } catch (error) {
    renderInvalidToken(error.message || t("auth.error.magic_link_invalid"));
    bindAuthEvents();
    return true;
  }
}
