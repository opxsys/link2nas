import { applyCurrentUserTheme } from "../../core/theme.js";
import { clearToken } from "../../core/session.js";
import { state } from "../../state.js";
import { showAppMessage } from "../../utils.js";
import { t } from "../../i18n/index.js";
import { getMe } from "../../api.js";
import { renderForcedPasswordChangeForm } from "../../render/auth.js";
import { loadAdmin } from "../admin-controller.js";
import {
  enterMainApplication,
  hideAdminIfNeeded,
  updateAuthVisibility,
} from "../navigation-controller.js";
import { bindAuthEvents } from "../auth-controller.js";

export async function resumeExistingSession({ existingToken }) {
  /*
   * Important:
   * - En multi-user sans token, /api/v2/me répond 401.
   * - En single-user, /api/v2/me retourne directement le user interne.
   * Donc on tente /me avant de rendre login/setup.
   */
  try {
    state.currentUser = await getMe();

    applyCurrentUserTheme(state.currentUser);

    if (state.currentUser?.single_user_mode) {
      clearToken();
      state.activeAdminTab = state.activeAdminTab === "users"
        ? "maintenance"
        : state.activeAdminTab;
    }

    updateAuthVisibility();

    if (state.currentUser?.force_password_change) {
      renderForcedPasswordChangeForm();
      bindAuthEvents();
      showAppMessage(t("messages.must_change_password"), "info");
      return true;
    }

    hideAdminIfNeeded();

    await enterMainApplication({ useHomePage: true });

    if (state.activePage === "admin") {
      await loadAdmin();
    }

    return true;
  } catch {
    if (existingToken) {
      clearToken();
    }
  }

  return false;
}
