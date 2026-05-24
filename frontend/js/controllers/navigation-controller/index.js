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
import { updateLanguageSwitchUI, updateMainNavUI } from "./navigation-ui.js";
import { resolveHomePage, renderPageVisibility } from "./page-routing.js";
export { hideAdminIfNeeded, updateAuthVisibility, openNavDrawer, closeNavDrawer, updateProwlarrNavVisibility } from "./navigation-ui.js";
export { resolveHomePage, setActivePage, renderPageVisibility } from "./page-routing.js";

let _bindGlobalEvents;

export function initNavigation({ bindGlobalEvents }) {
  _bindGlobalEvents = bindGlobalEvents;
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
