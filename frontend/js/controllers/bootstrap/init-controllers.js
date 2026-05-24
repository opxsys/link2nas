import { applyCurrentUserTheme } from "../../core/theme.js";
import {
  initNavigation,
  enterMainApplication,
  hideAdminIfNeeded,
  updateAuthVisibility,
  setActivePage,
} from "../navigation-controller.js";
import { initAnnouncements } from "../announcements-controller.js";
import { initAuth } from "../auth-controller.js";
import {
  initPublicRoutes,
  clearPublicAccountUrl,
} from "../public-routes-controller.js";

export function initBootstrapControllers({ bindGlobalEvents }) {
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
}
