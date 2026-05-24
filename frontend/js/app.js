import { applyTheme } from "./core/theme.js";
import { clearToken } from "./core/session.js";
import { state } from "./state.js";
import { showAppMessage } from "./utils.js";
import { t } from "./i18n/index.js";
import { updateMe, logout } from "./api.js";
import { renderForcedPasswordChangeForm } from "./render/auth.js";
import { loadSettings } from "./controllers/settings-controller.js";
import { navigateToPage } from "./controllers/app/page-navigation.js";
import { bindJobsEvents } from "./controllers/jobs-controller.js";
import { bindSettingsEvents } from "./events/settings-events.js";
import { bindAdminEvents } from "./events/admin-events.js";
import { bindAnnouncementsPageEvents } from "./controllers/announcements-controller.js";
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

    await navigateToPage(page);
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
    await navigateToPage(page);
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
  bindSettingsEvents();
  bindAdminEvents();

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
