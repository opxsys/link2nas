import { loadSettings } from "./controllers/settings-controller.js";
import { bindGlobalNavigationEvents } from "./controllers/app/global-navigation-events.js";
import { bindThemeEvents } from "./controllers/app/theme-events.js";
import { bindSessionEvents } from "./controllers/app/session-events.js";
import { bindJobsEvents } from "./controllers/jobs-controller.js";
import { bindSettingsEvents } from "./events/settings-events.js";
import { bindAdminEvents } from "./events/admin-events.js";
import { bindAnnouncementsPageEvents } from "./controllers/announcements-controller.js";
import { setActivePage } from "./controllers/navigation-controller.js";
import { run } from "./bootstrap.js";

let globalEventsBound = false;

function bindGlobalEvents() {
  if (globalEventsBound) return;
  globalEventsBound = true;

  bindGlobalNavigationEvents();

  bindThemeEvents();

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

  bindSessionEvents();
}

run(bindGlobalEvents).catch((error) => {
  console.error(error);
});
