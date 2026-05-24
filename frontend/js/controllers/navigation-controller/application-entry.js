import { state } from "../../state.js";
import { showMainApp } from "../../render/auth.js";
import { renderJobDetails } from "../../render/job-details.js";
import { loadSystemInfo } from "../../actions/system.js";
import { loadJobs } from "../../actions/jobs.js";
import { hasConfiguredProwlarr, renderProwlarrPanel } from "../../render/prowlarr.js";
import { loadSettings } from "../settings-controller.js";
import { startPolling } from "../jobs-controller.js";
import { bindBannerEvents } from "../announcements-controller.js";
import { resolveHomePage, renderPageVisibility } from "./page-routing.js";

let _bindGlobalEvents;

export function initApplicationEntry({ bindGlobalEvents }) {
  _bindGlobalEvents = bindGlobalEvents;
}

export async function enterMainApplication({ useHomePage = false } = {}) {
  showMainApp();
  renderJobDetails(null);
  _bindGlobalEvents();
  bindBannerEvents();

  await loadSettings();

  if (useHomePage) {
    state.activePage = resolveHomePage();
    localStorage.setItem("link2nas_active_page", state.activePage);
  } else if (state.activePage === "prowlarr" && !hasConfiguredProwlarr()) {
    state.activePage = "jobs";
    localStorage.setItem("link2nas_active_page", "jobs");
  }

  renderPageVisibility();

  await loadSystemInfo();
  await loadJobs();

  if (state.activePage === "prowlarr") {
    renderProwlarrPanel();
  }

  startPolling();
}
