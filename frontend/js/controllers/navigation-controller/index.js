import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { hasConfiguredProwlarr, renderProwlarrPanel } from "../../render/prowlarr.js";
import { renderCreateJobForm } from "../../render/forms.js";
import { renderJobDetails } from "../../render/job-details.js";
import { loadSystemInfo } from "../../actions/system.js";
import { loadJobs, selectJob } from "../../actions/jobs.js";
import { showMainApp } from "../../render/auth.js";
import { loadSettings } from "../settings-controller.js";
import { loadAdmin, initEmailTemplatesPanel } from "../admin-controller.js";
import { startPolling } from "../jobs-controller.js";
import {
  loadAnnouncements,
  renderAnnouncementBanner,
  pickBannerAnnouncement,
  updateAnnouncementBadge,
  bindBannerEvents,
} from "../announcements-controller.js";

let _bindGlobalEvents;

export function initNavigation({ bindGlobalEvents }) {
  _bindGlobalEvents = bindGlobalEvents;
}

export function hideAdminIfNeeded() {
  const adminButton = document.querySelector('[data-page="admin"]');
  const isSuperAdmin = state.currentUser?.role === "super_admin";

  if (adminButton) {
    adminButton.hidden = !isSuperAdmin;
  }

  if (!isSuperAdmin && state.activePage === "admin") {
    state.activePage = "jobs";
    localStorage.setItem("link2nas_active_page", "jobs");
  }
}

export function updateAuthVisibility() {
  const isAuthenticated = Boolean(state.currentUser);
  const mustChangePassword = Boolean(state.currentUser?.force_password_change);
  const isSingleUserMode = Boolean(state.currentUser?.single_user_mode);

  const mainNav = document.getElementById("main-nav");
  if (mainNav) {
    mainNav.hidden = !isAuthenticated || mustChangePassword;
  }

  const logoutButton = document.getElementById("logout-btn");
  if (logoutButton) {
    logoutButton.hidden = !isAuthenticated || isSingleUserMode;
  }
}

function updateLanguageSwitchUI() {
  document.querySelectorAll("#language-switch [data-lang]").forEach((button) => {
    const isActive = button.dataset.lang === state.language;
    button.classList.toggle("is-active", isActive);
  });
}

function updateMainNavUI() {
  updateProwlarrNavVisibility();

  document.querySelectorAll("#main-nav [data-page]").forEach((button) => {
    const isActive = button.dataset.page === state.activePage;
    button.classList.toggle("is-active", isActive);
  });
}

export function openNavDrawer() {
  const drawer = document.getElementById("nav-drawer");
  const overlay = document.getElementById("nav-drawer-overlay");
  const burgerBtn = document.getElementById("nav-burger-btn");

  if (drawer) drawer.classList.add("is-open");
  if (overlay) overlay.classList.add("is-open");
  if (burgerBtn) burgerBtn.setAttribute("aria-expanded", "true");
}

export function closeNavDrawer() {
  const drawer = document.getElementById("nav-drawer");
  const overlay = document.getElementById("nav-drawer-overlay");
  const burgerBtn = document.getElementById("nav-burger-btn");

  if (drawer) drawer.classList.remove("is-open");
  if (overlay) overlay.classList.remove("is-open");
  if (burgerBtn) burgerBtn.setAttribute("aria-expanded", "false");
}

export function updateProwlarrNavVisibility() {
  const prowlarrButton = document.querySelector('[data-page="prowlarr"]');
  if (!prowlarrButton) return;

  prowlarrButton.hidden = !hasConfiguredProwlarr();
}

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

export function renderStaticTexts() {
  const appHeader = document.querySelector(".app-header h1");
  if (appHeader && state.generalSettings?.app_name) {
    appHeader.textContent = state.generalSettings.app_name;
  }

  const appSubtitle = document.getElementById("app-subtitle");
  if (appSubtitle) {
    appSubtitle.textContent = state.generalSettings?.app_tagline || t("app.subtitle");
  }

  const jobsTitle = document.getElementById("jobs-title");
  if (jobsTitle) {
    jobsTitle.textContent = t("common.jobs");
  }

  const jobsStatusLabel = document.getElementById("jobs-status-label");
  if (jobsStatusLabel) {
    jobsStatusLabel.textContent = t("common.status");
  }

  const jobDetailsTitle = document.getElementById("job-details-title");
  if (jobDetailsTitle) {
    jobDetailsTitle.textContent = t("common.details");
  }

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.dataset.i18n;
    if (key) {
      el.textContent = t(key);
    }
  });

  document.querySelectorAll("[data-i18n-aria-label]").forEach((el) => {
    const key = el.dataset.i18nAriaLabel;
    if (key) {
      el.setAttribute("aria-label", t(key));
    }
  });

  document.documentElement.lang = state.language || "fr";
  updateLanguageSwitchUI();
  updateMainNavUI();
}

export async function rerenderAppForLanguageChange() {
  renderStaticTexts();
  renderPageVisibility();
  renderAnnouncementBanner(pickBannerAnnouncement(state.announcements));
  updateAnnouncementBadge(state.announcements);
  renderCreateJobForm();
  renderJobDetails(state.selectedJob);
  await loadSystemInfo();
  await loadJobs();

  if (state.selectedJobId) {
    await selectJob(state.selectedJobId);
  }

  if (state.activePage === "settings") {
    await loadSettings();
  }

  if (state.activePage === "admin") {
    await loadAdmin();
    if (state.activeAdminTab === "email-templates") {
      await initEmailTemplatesPanel();
    }
  }

  if (state.activePage === "announcements") {
    await loadAnnouncements();
  }

  if (state.activePage === "prowlarr") {
    renderProwlarrPanel();
  }

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
