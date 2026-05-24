import { applyTheme } from "./core/theme.js";
import { getToken, startInactivityWatch } from "./core/session.js";
import { state } from "./state.js";
import { renderAuthEntryPoint } from "./controllers/bootstrap/auth-entry-bootstrap.js";
import {
  hideAdminIfNeeded,
  updateAuthVisibility,
  renderStaticTexts,
} from "./controllers/navigation-controller.js";
import { resumeExistingSession } from "./controllers/bootstrap/session-bootstrap.js";
import { handlePublicAccountRoute } from "./controllers/public-routes-controller.js";
import { bindPublicEvents } from "./controllers/bootstrap/public-events.js";
import { initBootstrapControllers } from "./controllers/bootstrap/init-controllers.js";

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

  const resumedSession = await resumeExistingSession({ existingToken });
  if (resumedSession) {
    return;
  }

  await renderAuthEntryPoint();
}

export async function run(bindGlobalEvents) {
  initBootstrapControllers({ bindGlobalEvents });

  await bootstrap();
}
