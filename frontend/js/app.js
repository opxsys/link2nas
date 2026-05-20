import { applyTheme } from "./core/theme.js";
import { clearToken } from "./core/session.js";
import { state } from "./state.js";
import { renderJobDetails } from "./render/job-details.js";
import { loadJobs } from "./actions/jobs.js";
import { loadSystemInfo } from "./actions/system.js";
import { showAppMessage } from "./utils.js";
import { t } from "./i18n/index.js";
import {
  updateMe,
  logout,
  requestEmailVerification,
  testNotificationConfig,
} from "./api.js";
import { renderForcedPasswordChangeForm } from "./render/auth.js";
import {
  updateDestinationFields,
  updateNotificationChannelFields,
} from "./render/settings.js";
import { renderProwlarrPanel } from "./render/prowlarr.js";
import {
  loadSettings,
  handleSettingsSubmit,
  handleSettingsClick,
} from "./controllers/settings-controller.js";
import {
  loadAdmin,
  handleAdminSubmit,
  handleAdminClick,
  switchAdminTab,
  updateUserCreationModeFields,
  initEmailTemplatesPanel,
  loadAntiAbuseSection,
  loadEmailTemplateIntoPanel,
} from "./controllers/admin-controller.js";
import { bindJobsEvents } from "./controllers/jobs-controller.js";
import {
  loadAnnouncements,
  bindAnnouncementsPageEvents,
} from "./controllers/announcements-controller.js";
import {
  closeNavDrawer,
  openNavDrawer,
  setActivePage,
  resolveHomePage,
  updateAuthVisibility,
} from "./controllers/navigation-controller.js";
import { run } from "./bootstrap.js";

let globalEventsBound = false;

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
    clearToken();
    location.reload();
  });
}

run(bindGlobalEvents).catch((error) => {
  console.error(error);
});
