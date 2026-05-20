import { state } from "./state.js";
import { renderJobDetails } from "./render/job-details.js";
import { loadJobs } from "./actions/jobs.js";

import { loadSystemInfo } from "./actions/system.js";
import { showAppMessage } from "./utils.js";
import { t } from "./i18n/index.js";
import {
  getSetupStatus,
  getMe,
  logout,
  updateMe,
  requestEmailVerification,
  testNotificationConfig,
  getPublicAppInfo,
} from "./api.js";

import {
  renderSetupForm,
  renderLoginForm,
  renderForcedPasswordChangeForm,
} from "./render/auth.js";

import {
  updateDestinationFields,
  updateNotificationChannelFields,
} from "./render/settings.js";

import { renderProwlarrPanel, hasConfiguredProwlarr } from "./render/prowlarr.js";
import {
  loadSettings,
  handleSettingsSubmit,
  handleSettingsClick,
  onSettingsTabChange,
  loadEspace,
} from "./controllers/settings-controller.js";
import {
  loadAdmin,
  handleAdminSubmit,
  handleAdminClick,
  switchAdminTab,
  bindAdminUsersFilters,
  updateUserCreationModeFields,
  initEmailTemplatesPanel,
  loadAntiAbuseSection,
  loadEmailTemplateIntoPanel,
} from "./controllers/admin-controller.js";
import { bindJobsEvents } from "./controllers/jobs-controller.js";
import {
  initAnnouncements,
  loadAnnouncements,
  bindAnnouncementsPageEvents,
} from "./controllers/announcements-controller.js";
import { initAuth, bindAuthEvents } from "./controllers/auth-controller.js";
import {
  initPublicRoutes,
  handlePublicAccountRoute,
  clearPublicAccountUrl,
} from "./controllers/public-routes-controller.js";
import {
  initNavigation,
  enterMainApplication,
  hideAdminIfNeeded,
  updateAuthVisibility,
  openNavDrawer,
  closeNavDrawer,
  updateProwlarrNavVisibility,
  resolveHomePage,
  setActivePage,
  renderPageVisibility,
  renderStaticTexts,
  rerenderAppForLanguageChange,
} from "./controllers/navigation-controller.js";

let inactivityTimer;
let publicEventsBound = false;
let globalEventsBound = false;
const DEFAULT_SESSION_INACTIVITY_MINUTES = 30;


function getSessionInactivityMinutes() {
  const raw = Number(state.currentUser?.session_inactivity_minutes);

  if (Number.isFinite(raw) && raw >= 5) {
    return raw;
  }

  return DEFAULT_SESSION_INACTIVITY_MINUTES;
}

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);

  const minutes = getSessionInactivityMinutes();

  inactivityTimer = setTimeout(() => {
    localStorage.removeItem("link2nas_token");
    location.reload();
  }, minutes * 60 * 1000);
}

["click", "mousemove", "keydown"].forEach((eventName) => {
  document.addEventListener(eventName, resetInactivityTimer);
});

let _themeMediaListener = null;

export function applyCurrentUserTheme(user) {
  const theme = user?.ui_theme || "auto";
  applyTheme(theme);
  localStorage.setItem("link2nas_theme", theme);
}

function applyTheme(stored) {
  if (_themeMediaListener) {
    window.matchMedia("(prefers-color-scheme: dark)").removeEventListener("change", _themeMediaListener);
    _themeMediaListener = null;
  }
  const valid = new Set(["auto", "light", "night", "high_contrast", "colorblind"]);
  const pref = valid.has(stored) ? stored : "auto";
  let resolved = pref;
  if (pref === "auto") {
    resolved = window.matchMedia("(prefers-color-scheme: dark)").matches ? "night" : "light";
    _themeMediaListener = (e) => {
      document.documentElement.dataset.theme = e.matches ? "night" : "light";
    };
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", _themeMediaListener);
  }
  document.documentElement.dataset.theme = resolved;
}

function bindGlobalEvents() {
  if (globalEventsBound) return;
  globalEventsBound = true;

  document.getElementById("main-nav")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-page]");
    if (!button) return;

    if (state.currentUser?.force_password_change) {
      renderForcedPasswordChangeForm();
      showAppMessage(t("messages.must_change_password"), "info");
      closeNavDrawer();
      return;
    }

    const page = button.dataset.page;

    if (!page || page === state.activePage) {
      closeNavDrawer();
      return;
    }

    closeNavDrawer();
    setActivePage(page);

    if (page === "jobs") {
      await loadSettings();
      renderJobDetails(state.selectedJob);
      await loadJobs();
    }

    if (page === "prowlarr") {
      renderProwlarrPanel();
    }

    if (page === "control-center") {
      await loadSystemInfo();
    }

    if (page === "settings") {
      await loadSettings();
    }

    if (page === "announcements") {
      await loadAnnouncements();
    }

    if (page === "admin") {
      await loadAdmin();
    }
  });

  // Theme select — apply immediately on change
  document.addEventListener("change", async (event) => {
    const select = event.target.closest("select[name='ui_theme']");
    if (!select) return;
    const theme = select.value;
    applyTheme(theme);
    localStorage.setItem("link2nas_theme", theme);
    if (state.currentUser) {
      try { await updateMe({ ui_theme: theme }); } catch {}
      if (state.currentUser) state.currentUser.ui_theme = theme;
    }
  });

  // App brand click — navigate to home page
  document.getElementById("app-brand-btn")?.addEventListener("click", async () => {
    if (!state.currentUser) return;
    if (state.currentUser.force_password_change) return;
    closeNavDrawer();
    const page = resolveHomePage();
    if (page === state.activePage) return;
    setActivePage(page);
    if (page === "jobs") {
      await loadSettings();
      renderJobDetails(state.selectedJob);
      await loadJobs();
    }
    if (page === "prowlarr") {
      renderProwlarrPanel();
    }
    if (page === "control-center") {
      await loadSystemInfo();
    }
  });

  // Burger button toggle
  document.getElementById("nav-burger-btn")?.addEventListener("click", () => {
    const drawer = document.getElementById("nav-drawer");
    if (drawer?.classList.contains("is-open")) {
      closeNavDrawer();
    } else {
      openNavDrawer();
    }
  });

  // Close drawer on overlay click
  document.getElementById("nav-drawer-overlay")?.addEventListener("click", () => {
    closeNavDrawer();
  });

  // Close drawer on close button click
  document.getElementById("nav-drawer-close")?.addEventListener("click", () => {
    closeNavDrawer();
  });

  // Close drawer on Escape key
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      const drawer = document.getElementById("nav-drawer");
      if (drawer?.classList.contains("is-open")) {
        closeNavDrawer();
      }
    }
  });

  bindJobsEvents();

  document.getElementById("prowlarr-page")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) return;

    if (button.dataset.action === "go-settings") {
      setActivePage("settings");
      await loadSettings();
    }
  });

  bindAnnouncementsPageEvents();

  document.getElementById("settings-page")?.addEventListener("change", (event) => {
    if (event.target?.id === "destination-name") {
      updateDestinationFields();
      return;
    }

  if (event.target?.id === "notification-channel") {
    updateNotificationChannelFields();
    return;
  }
  });

  document.getElementById("settings-page")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    try {
      await handleSettingsSubmit(event.target);
    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });

  document.getElementById("settings-page")?.addEventListener("click", async (event) => {
    const requestButton = event.target.closest("#request-email-verification-btn");
    if (requestButton) {
      if (!state.currentUser?.email_sending_available) {
        showAppMessage(t("email.smtp_configure_hint"), "error");
        return;
      }

      requestButton.disabled = true;

      try {
        const result = await requestEmailVerification();
        showAppMessage(result.message || t("messages.email_verification_sent"), "success");
      } catch (error) {
        showAppMessage(error.message || t("messages.email_verification_error"), "error");
      } finally {
        requestButton.disabled = false;
      }

      return;
    }

    const testEmailButton = event.target.closest("#test-email-notification-btn");
    if (testEmailButton) {
      try {
        const result = await testNotificationConfig({
          channel: "email",
          config: {},
        });

        showAppMessage(result.message || t("messages.settings_channel_test_ok"), "success");
      } catch (error) {
        showAppMessage(error.message || t("messages.settings_action_error"), "error");
      }
      return;
    }

    const button = event.target.closest("[data-settings-action], [data-action]");
    if (!button) return;

    try {
      await handleSettingsClick(button);
    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });

  document.getElementById("admin-page")?.addEventListener("change", (event) => {
    if (event.target?.id === "user-creation-mode") {
      updateUserCreationModeFields();
    }

    if (
      event.target?.id === "email-template-key-select" ||
      event.target?.id === "email-template-lang-select"
    ) {
      const key = document.getElementById("email-template-key-select")?.value;
      const lang = document.getElementById("email-template-lang-select")?.value;
      if (key && lang) {
        loadEmailTemplateIntoPanel(key, lang);
      }
    }
  });

  document.getElementById("admin-page")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    try {
      await handleAdminSubmit(event.target);
    } catch (error) {
      showAppMessage(error.message || t("messages.admin_action_error"), "error");
    }
  });

  document.getElementById("admin-page")?.addEventListener("click", async (event) => {
    const tabButton = event.target.closest("[data-admin-tab]");
    if (tabButton) {
      state.activeAdminTab = tabButton.dataset.adminTab || "users";
      switchAdminTab(state.activeAdminTab);
      if (state.activeAdminTab === "email-templates") {
        await initEmailTemplatesPanel();
      }
      if (state.activeAdminTab === "security") {
        await loadAntiAbuseSection();
      }
      return;
    }

    const button = event.target.closest("[data-action]");
    if (!button) return;

    try {
      await handleAdminClick(button);
    } catch (error) {
      showAppMessage(error.message || t("messages.admin_action_error"), "error");
    }
  });

  document.getElementById("logout-btn")?.addEventListener("click", async () => {
    closeNavDrawer();

    try {
      await logout();
    } catch {}

    state.currentUser = null;
    updateAuthVisibility();
    localStorage.removeItem("link2nas_token");
    location.reload();
  });
}

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
  resetInactivityTimer();
  updateAuthVisibility();
  hideAdminIfNeeded();

  const handledPublicRoute = await handlePublicAccountRoute();
  if (handledPublicRoute) {
    return;
  }

  const existingToken = localStorage.getItem("link2nas_token");

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
      localStorage.removeItem("link2nas_token");
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
      localStorage.removeItem("link2nas_token");
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

bootstrap().catch((error) => {
  console.error(error);
});