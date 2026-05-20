import { applyTheme, applyCurrentUserTheme } from "./core/theme.js";
import { getToken, clearToken, startInactivityWatch } from "./core/session.js";
import { state } from "./state.js";
import { showAppMessage } from "./utils.js";
import { t } from "./i18n/index.js";
import { getSetupStatus, getMe, getPublicAppInfo } from "./api.js";
import {
  renderSetupForm,
  renderLoginForm,
  renderForcedPasswordChangeForm,
} from "./render/auth.js";
import { loadAdmin } from "./controllers/admin-controller.js";
import {
  initNavigation,
  enterMainApplication,
  hideAdminIfNeeded,
  updateAuthVisibility,
  setActivePage,
  renderStaticTexts,
  rerenderAppForLanguageChange,
  closeNavDrawer,
} from "./controllers/navigation-controller.js";
import { initAnnouncements } from "./controllers/announcements-controller.js";
import { initAuth, bindAuthEvents } from "./controllers/auth-controller.js";
import {
  initPublicRoutes,
  handlePublicAccountRoute,
  clearPublicAccountUrl,
} from "./controllers/public-routes-controller.js";

let publicEventsBound = false;

function bindPublicEvents() {
  if (publicEventsBound) return;
  publicEventsBound = true;

  document.getElementById("language-switch")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-lang]");
    if (!button) return;

    const lang = button.dataset.lang;
    if (!lang || lang === state.language) return;

    closeNavDrawer();

    state.language = lang;
    localStorage.setItem("link2nas_language", lang);

    if (state.currentUser) {
      await rerenderAppForLanguageChange();
      return;
    }

    renderStaticTexts();

    const setupStatus = await getSetupStatus();
    if (setupStatus.setup_required) {
      renderSetupForm();
    } else {
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
    }

    bindAuthEvents();
  });
}

async function bootstrap() {
  applyTheme(localStorage.getItem("link2nas_theme") || "auto");

  const savedLanguage = localStorage.getItem("link2nas_language");

  if (savedLanguage) {
    state.language = savedLanguage;
  }

  renderStaticTexts();
  bindPublicEvents();
  startInactivityWatch();
  updateAuthVisibility();
  hideAdminIfNeeded();

  const handledPublicRoute = await handlePublicAccountRoute();
  if (handledPublicRoute) {
    return;
  }

  const existingToken = getToken();

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
      return;
    }

    hideAdminIfNeeded();

    await enterMainApplication({ useHomePage: true });

    if (state.activePage === "admin") {
      await loadAdmin();
    }

    return;
  } catch {
    if (existingToken) {
      clearToken();
    }
  }

  const setupStatus = await getSetupStatus();

  if (setupStatus.setup_required) {
    renderSetupForm();
    bindAuthEvents();
    return;
  }

  let appInfoEmailAvailable = true;
  try {
    const appInfo = await getPublicAppInfo();
    state.appInfo = appInfo;
    appInfoEmailAvailable = appInfo?.email_sending_available ?? true;
  } catch {
    // Non bloquant — on affiche le bouton magic login par défaut
  }

  renderLoginForm(appInfoEmailAvailable);
  bindAuthEvents();
}

export async function run(bindGlobalEvents) {
  initNavigation({ bindGlobalEvents });
  initAnnouncements({ setActivePage });
  initAuth({
    enterMainApplication,
    hideAdminIfNeeded,
    updateAuthVisibility,
    clearPublicAccountUrl,
    applyCurrentUserTheme,
  });
  initPublicRoutes({
    updateAuthVisibility,
    enterMainApplication,
    hideAdminIfNeeded,
    applyCurrentUserTheme,
  });

  await bootstrap();
}
