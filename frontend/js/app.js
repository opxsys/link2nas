import { applyTheme } from "./core/theme.js";
import { clearToken } from "./core/session.js";
import { state } from "./state.js";
import { updateMe, logout } from "./api.js";
import { loadSettings } from "./controllers/settings-controller.js";
import { bindGlobalNavigationEvents } from "./controllers/app/global-navigation-events.js";
import { bindJobsEvents } from "./controllers/jobs-controller.js";
import { bindSettingsEvents } from "./events/settings-events.js";
import { bindAdminEvents } from "./events/admin-events.js";
import { bindAnnouncementsPageEvents } from "./controllers/announcements-controller.js";
import {
  closeNavDrawer,
  setActivePage,
  updateAuthVisibility,
} from "./controllers/navigation-controller.js";
import { run } from "./bootstrap.js";

let globalEventsBound = false;

function bindGlobalEvents() {
  if (globalEventsBound) return;
  globalEventsBound = true;

  bindGlobalNavigationEvents();

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
