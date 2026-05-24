import { state } from "../../state.js";
import { hasConfiguredProwlarr, renderProwlarrPanel } from "../../render/prowlarr.js";
import { updateMainNavUI } from "./navigation-ui.js";

export function resolveHomePage() {
  const settings = state.integrationSettings || {};
  const requested = settings.home_page || "jobs";

  if (requested === "prowlarr") {
    return hasConfiguredProwlarr() ? "prowlarr" : "jobs";
  }

  if (requested === "control-center") {
    return "control-center";
  }

  return "jobs";
}

export function setActivePage(page, persist = true) {
  const target = page || "jobs";

  state.activePage = target;

  if (persist) {
    localStorage.setItem("link2nas_active_page", target);
  }

  renderPageVisibility();
}

export function renderPageVisibility() {
  if (state.activePage === "prowlarr" && !hasConfiguredProwlarr()) {
    state.activePage = "jobs";
    localStorage.setItem("link2nas_active_page", "jobs");
  }

  const jobsPage = document.getElementById("jobs-page");
  const prowlarrPage = document.getElementById("prowlarr-page");
  const controlCenterPage = document.getElementById("control-center-page");
  const settingsPage = document.getElementById("settings-page");
  const announcementsPage = document.getElementById("announcements-page");
  const adminPage = document.getElementById("admin-page");

  if (jobsPage) jobsPage.hidden = state.activePage !== "jobs";
  if (prowlarrPage) prowlarrPage.hidden = state.activePage !== "prowlarr";
  if (controlCenterPage) controlCenterPage.hidden = state.activePage !== "control-center";
  if (settingsPage) settingsPage.hidden = state.activePage !== "settings";
  if (announcementsPage) announcementsPage.hidden = state.activePage !== "announcements";
  if (adminPage) adminPage.hidden = state.activePage !== "admin";

  if (state.activePage === "prowlarr") {
    renderProwlarrPanel();
  }

  updateMainNavUI();
}
