import { ACTIVE_STATUSES, JOBS_POLL_MS } from "./config.js";
import { state } from "./state.js";
import {
  renderCreateJobForm,
  updateCreateJobDestinationVisibility,
} from "./render/forms.js";
import { renderJobDetails } from "./render/job-details.js";
import {
  loadJobs,
  createNewJob,
  createTorrentFilesBatch,
  performJobAction,
  selectJob,
  refreshSelectedJob,
} from "./actions/jobs.js";

import { loadSystemInfo } from "./actions/system.js";
import { showAppMessage } from "./utils.js";
import { t } from "./i18n/index.js";
import {
  getSetupStatus,
  getMe,
  logout,
  updateMe,
  requestEmailVerification,
  testNotificationConfig,
  getPublicAppInfo,
  listActiveAnnouncements,
  openAnnouncement,
  readAnnouncement,
  acknowledgeAnnouncement,
} from "./api.js";

import {
  renderSetupForm,
  renderLoginForm,
  renderForcedPasswordChangeForm,
} from "./render/auth.js";

import {
  updateDestinationFields,
  updateNotificationChannelFields,
} from "./render/settings.js";

import { renderAnnouncementsPage } from "./render/announcements.js";
import { renderProwlarrPanel, hasConfiguredProwlarr } from "./render/prowlarr.js";
import {
  showConfirmModal,
  showLinkModal,
  showSecretModal,
  escapeForModalHtml,
} from "./ui/modals.js";
import {
  loadSettings,
  handleSettingsSubmit,
  handleSettingsClick,
  onSettingsTabChange,
  loadEspace,
} from "./controllers/settings-controller.js";
import {
  loadAdmin,
  handleAdminSubmit,
  handleAdminClick,
  switchAdminTab,
  bindAdminUsersFilters,
  updateUserCreationModeFields,
  initEmailTemplatesPanel,
  loadAntiAbuseSection,
  loadEmailTemplateIntoPanel,
} from "./controllers/admin-controller.js";
import { initAuth, bindAuthEvents } from "./controllers/auth-controller.js";
import {
  initPublicRoutes,
  handlePublicAccountRoute,
  clearPublicAccountUrl,
} from "./controllers/public-routes-controller.js";
import {
  initNavigation,
  enterMainApplication,
  hideAdminIfNeeded,
  updateAuthVisibility,
  openNavDrawer,
  closeNavDrawer,
  updateProwlarrNavVisibility,
  resolveHomePage,
  setActivePage,
  renderPageVisibility,
  renderStaticTexts,
  rerenderAppForLanguageChange,
} from "./controllers/navigation-controller.js";

let inactivityTimer;
let publicEventsBound = false;
let globalEventsBound = false;
const DEFAULT_SESSION_INACTIVITY_MINUTES = 30;


const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };

function getSessionInactivityMinutes() {
  const raw = Number(state.currentUser?.session_inactivity_minutes);

  if (Number.isFinite(raw) && raw >= 5) {
    return raw;
  }

  return DEFAULT_SESSION_INACTIVITY_MINUTES;
}

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);

  const minutes = getSessionInactivityMinutes();

  inactivityTimer = setTimeout(() => {
    localStorage.removeItem("link2nas_token");
    location.reload();
  }, minutes * 60 * 1000);
}

["click", "mousemove", "keydown"].forEach((eventName) => {
  document.addEventListener(eventName, resetInactivityTimer);
});

let _themeMediaListener = null;

export function applyCurrentUserTheme(user) {
  const theme = user?.ui_theme || "auto";
  applyTheme(theme);
  localStorage.setItem("link2nas_theme", theme);
}

function applyTheme(stored) {
  if (_themeMediaListener) {
    window.matchMedia("(prefers-color-scheme: dark)").removeEventListener("change", _themeMediaListener);
    _themeMediaListener = null;
  }
  const valid = new Set(["auto", "light", "night", "high_contrast", "colorblind"]);
  const pref = valid.has(stored) ? stored : "auto";
  let resolved = pref;
  if (pref === "auto") {
    resolved = window.matchMedia("(prefers-color-scheme: dark)").matches ? "night" : "light";
    _themeMediaListener = (e) => {
      document.documentElement.dataset.theme = e.matches ? "night" : "light";
    };
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", _themeMediaListener);
  }
  document.documentElement.dataset.theme = resolved;
}

function pickBannerAnnouncement(announcements) {
  const dismissed = state.dismissedAnnouncementBannerIds;
  const bannerCandidates = (announcements || []).filter((a) => {
    if (!a.show_as_banner) return false;
    if (dismissed.includes(a.id)) return false;
    const status = a.user_status || {};
    if (Boolean(a.require_acknowledgement) && status.acknowledged_at) return false;
    if (!a.require_acknowledgement && status.read_at) return false;
    return true;
  });
  if (!bannerCandidates.length) return null;
  return bannerCandidates.sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 3;
    const sb = SEVERITY_ORDER[b.severity] ?? 3;
    if (sa !== sb) return sa - sb;
    return (b.created_at || "").localeCompare(a.created_at || "");
  })[0];
}

function renderAnnouncementBanner(ann) {
  const banner = document.getElementById("announcement-banner");
  if (!banner) return;

  if (!ann) {
    banner.hidden = true;
    banner.className = "";
    banner.innerHTML = "";
    return;
  }

  const severityClass = `announcement-severity-${ann.severity || "info"}`;
  banner.className = severityClass;
  banner.hidden = false;

  const bodyPreview = String(ann.body || "").slice(0, 200);
  const status = ann.user_status || {};
  const needsAck = Boolean(ann.require_acknowledgement) && !status.acknowledged_at;
  const needsRead = !status.read_at;

  const esc = escapeForModalHtml;

  banner.innerHTML = `
    <div class="announcement-banner-content">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span class="announcement-severity-badge severity-${esc(ann.severity || "info")}">${esc(formatSeverityLabel(ann.severity))}</span>
        <span class="announcement-banner-title">${esc(ann.title)}</span>
      </div>
      <div class="announcement-banner-body">${esc(bodyPreview)}</div>
    </div>
    <div class="announcement-banner-actions">
      ${needsAck
        ? `<button class="btn btn-primary" data-banner-action="acknowledge" data-ann-id="${esc(ann.id)}">${t("announcements.acknowledge")}</button>`
        : needsRead
          ? `<button class="btn" data-banner-action="read" data-ann-id="${esc(ann.id)}">${t("announcements.mark_read")}</button>`
          : ""}
      <button class="btn" data-banner-action="view" data-ann-id="${esc(ann.id)}" data-track-open="${ann.track_open ? "1" : "0"}">${t("announcements.view")}</button>
      <button class="announcement-banner-close" data-banner-action="dismiss" data-ann-id="${esc(ann.id)}" title="${t("announcements.dismiss")}">✕</button>
    </div>
  `;
}

function formatSeverityLabel(severity) {
  if (severity === "critical") return t("admin.announcements.severity_critical");
  if (severity === "warning") return t("admin.announcements.severity_warning");
  return t("admin.announcements.severity_info");
}

async function refreshAnnouncementsState() {
  try {
    const announcements = await listActiveAnnouncements();
    state.announcements = Array.isArray(announcements) ? announcements : [];
  } catch {
    // non-critical
  }
  renderAnnouncementBanner(pickBannerAnnouncement(state.announcements));
  updateAnnouncementBadge(state.announcements);
  if (state.activePage === "announcements") {
    renderAnnouncementsPage(state.announcements, state.currentUser?.role === "super_admin");
  }
}

export async function loadAndRenderBanner() {
  try {
    const announcements = await listActiveAnnouncements();
    state.announcements = Array.isArray(announcements) ? announcements : [];
    const top = pickBannerAnnouncement(state.announcements);
    renderAnnouncementBanner(top);
    updateAnnouncementBadge(state.announcements);
  } catch {
    // banner is non-critical — silently ignore
  }
}

function announcementNeedsAttention(ann) {
  if (Boolean(ann.require_acknowledgement)) return !ann.user_status?.acknowledged_at;
  return !ann.user_status?.read_at;
}

function getAnnouncementsUnreadCount(announcements) {
  return (announcements || []).filter(announcementNeedsAttention).length;
}

function updateAnnouncementBadge(announcements) {
  const badge = document.getElementById("announcements-badge");
  if (!badge) return;
  const count = getAnnouncementsUnreadCount(announcements);
  if (count > 0) {
    badge.textContent = count > 99 ? "99+" : String(count);
    badge.hidden = false;
  } else {
    badge.hidden = true;
  }
}

async function loadAnnouncements() {
  try {
    const announcements = await listActiveAnnouncements();
    state.announcements = Array.isArray(announcements) ? announcements : [];
  } catch {
    state.announcements = [];
  }

  renderAnnouncementsPage(state.announcements, state.currentUser?.role === "super_admin");
  updateAnnouncementBadge(state.announcements);
  renderAnnouncementBanner(pickBannerAnnouncement(state.announcements));

  // silently track opens for applicable announcements
  for (const ann of state.announcements) {
    if (ann.track_open && !(ann.user_status?.opened_at)) {
      openAnnouncement(ann.id).catch(() => {});
    }
  }
}

function bindBannerEvents() {
  const banner = document.getElementById("announcement-banner");
  if (!banner) return;

  banner.addEventListener("click", async (event) => {
    const btn = event.target.closest("[data-banner-action]");
    if (!btn) return;

    const bannerAction = btn.dataset.bannerAction;
    const annId = btn.dataset.annId;
    if (!annId) return;

    if (bannerAction === "dismiss") {
      if (!state.dismissedAnnouncementBannerIds.includes(annId)) {
        state.dismissedAnnouncementBannerIds.push(annId);
      }
      renderAnnouncementBanner(pickBannerAnnouncement(state.announcements));
      return;
    }

    if (bannerAction === "view") {
      setActivePage("announcements");
      await loadAnnouncements();
      return;
    }

    if (bannerAction === "read") {
      try {
        await readAnnouncement(annId);
        await refreshAnnouncementsState();
      } catch (error) {
        showAppMessage(error.message || t("messages.admin_action_error"), "error");
      }
      return;
    }

    if (bannerAction === "acknowledge") {
      try {
        await acknowledgeAnnouncement(annId);
        await refreshAnnouncementsState();
      } catch (error) {
        showAppMessage(error.message || t("messages.admin_action_error"), "error");
      }
      return;
    }
  });
}

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

  document.getElementById("jobs-status-filter")?.addEventListener("change", async (event) => {
    state.jobsStatusFilter = event.target.value;
    await loadJobs();

    if (state.selectedJobId) {
      const stillThere = state.jobs.find((job) => job.id === state.selectedJobId);

      if (stillThere) {
        await selectJob(state.selectedJobId);
      } else {
        state.selectedJobId = null;
        state.selectedJob = null;
        renderJobDetails(null);
      }
    }
  });
  document.getElementById("create-job-panel")?.addEventListener("change", (event) => {
    if (event.target?.name === "send_to_destination") {
      updateCreateJobDestinationVisibility();
    }
  });
  document.getElementById("create-job-panel")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;

    const rawText = form.source_value.value;

    const sources = rawText
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);

    const seen = new Set();
    const duplicateLines = sources.filter(line => {
      if (seen.has(line)) return true;
      seen.add(line);
      return false;
    });
    const uniqueSources = [...seen];
    const files = Array.from(form.torrent_file?.files || []);
    const file = files[0] || null;
    const invalidSources = uniqueSources.filter((line) => {
      return !line.startsWith("magnet:?")
        && !/^https?:\/\//i.test(line);
    });

    const validSources = uniqueSources.filter((line) => {
      return line.startsWith("magnet:?")
        || /^https?:\/\//i.test(line);
    });

    const invalidResults = invalidSources.map((line) => ({
      filename: line,
      ok: false,
      error: t("messages.invalid_source_line"),
    }));
    const duplicateResults = duplicateLines.map((line) => ({
      filename: line,
      ok: false,
      error: t("messages.duplicate_source_ignored"),
    }));

    let pendingBatchResults = null;

    if (validSources.length === 0 && !file) {
      if (invalidResults.length > 0 || duplicateResults.length > 0) {
        pendingBatchResults = [...invalidResults, ...duplicateResults];
      } else {
        showAppMessage(t("messages.no_valid_source"), "error");
        return;
      }
    } else {
      const sourceValue = validSources.join("\n");
      form.source_value.value = sourceValue;

      const autoStart = Boolean(form.auto_start?.checked);
      const sendToDestination = Boolean(form.send_to_destination?.checked);

      const providerConfigId = form.provider_config_id?.value || null;
      const destinationConfigId = sendToDestination
        ? (form.destination_config_id?.value || null)
        : null;

      if (sourceValue && file) {
        pendingBatchResults = [{
          filename: t("form.create_jobs"),
          ok: false,
          error: t("messages.choose_text_or_file"),
        }];
      }

      if (!sourceValue && !file) {
        showAppMessage(t("messages.provide_source"), "info");
        return;
      }

      if (pendingBatchResults === null && files.length > 0) {
        const results = await createTorrentFilesBatch({
          files,
          autoStart,
          sendToDestination,
          providerConfigId,
          destinationConfigId,
        });

        pendingBatchResults = results;
      } else if (pendingBatchResults === null) {
        const entries = await createNewJob({
          source_type: "bulk_text",
          source_value: sourceValue,
          auto_start: autoStart,
          send_to_destination: sendToDestination,
          provider_config_id: providerConfigId,
          destination_config_id: destinationConfigId,
        });

        const batchResults = (entries || []).map((entry) => ({
          filename: entry.job?.source_value || entry.job?.filename || entry.job?.id || "Source",
          ok: true,
          error: null,
          job: entry.job,
          job_id: entry.job?.id,
          reused: Boolean(entry.reused),
        }));

        pendingBatchResults = [...batchResults, ...invalidResults, ...duplicateResults];
      }
    }

    form.reset();
    renderCreateJobForm();

    if (pendingBatchResults?.length > 0) {
      showBatchResultPanel(pendingBatchResults);
    }

    if (form.auto_start) {
      form.auto_start.checked = true;
    }

    if (form.send_to_destination) {
      form.send_to_destination.checked = false;
    }

    setActivePage("jobs");
  });

  document.getElementById("jobs-list")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) return;

    const action = button.dataset.action;
    const jobId = button.dataset.jobId;

    if (action === "delete") {
      await performJobAction("delete", jobId);
    }
  });

  document.getElementById("job-details")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) return;

    const action = button.dataset.action;
    const jobId = button.dataset.jobId;
    const fileId = button.dataset.fileId;

    await performJobAction(action, jobId, fileId);
  });

  document.getElementById("prowlarr-page")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-action]");
    if (!button) return;

    if (button.dataset.action === "go-settings") {
      setActivePage("settings");
      await loadSettings();
    }
  });

  document.getElementById("announcements-page")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-ann-action]");
    if (!button) return;

    const annAction = button.dataset.annAction;

    if (annAction === "goto-create-announcement") {
      setActivePage("admin");
      await loadAdmin();
      state.activeAdminTab = "announcements";
      switchAdminTab("announcements");
      const createBlock = document.querySelector('[data-admin-panel="announcements"] .admin-create-user-block');
      if (createBlock) createBlock.open = true;
      return;
    }

    const annId = button.dataset.annId;
    if (!annId) return;

    button.disabled = true;
    try {
      if (annAction === "read") {
        await readAnnouncement(annId);
      } else if (annAction === "acknowledge") {
        await acknowledgeAnnouncement(annId);
      }
      await loadAnnouncements();
    } catch (error) {
      showAppMessage(error.message || t("messages.admin_action_error"), "error");
    } finally {
      button.disabled = false;
    }
  });

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

  document.addEventListener("click", async (event) => {
    const card = event.target.closest(".job-card");
    if (!card) return;

    if (event.target.closest("button, input, select, textarea, label, details, summary, form")) return;

    const jobId = card.dataset.jobId;
    if (!jobId) return;

    await selectJob(jobId);

    setActivePage("jobs");
  });

  document.getElementById("logout-btn")?.addEventListener("click", async () => {
    closeNavDrawer();

    try {
      await logout();
    } catch {}

    state.currentUser = null;
    updateAuthVisibility();
    localStorage.removeItem("link2nas_token");
    location.reload();
  });
}

function startPolling() {
  clearInterval(state.jobsPollTimer);
  clearInterval(state.systemPollTimer);

  state.jobsPollTimer = setInterval(async () => {
    await loadJobs();

    if (!state.selectedJobId) return;

    const selectedFromList = state.jobs.find((job) => job.id === state.selectedJobId);

    if (!selectedFromList) {
      state.selectedJobId = null;
      state.selectedJob = null;
      renderJobDetails(null);
      return;
    }

    const selectedStatus = String(selectedFromList.status || "").trim().toLowerCase();
    const selectedDestinationStatus = String(selectedFromList.destination_status || "").trim().toLowerCase();

    const shouldRefreshDetails =
      ACTIVE_STATUSES.has(selectedStatus) ||
      ["queued", "sending", "downloading", "cancel_requested"].includes(selectedDestinationStatus) ||
      selectedStatus === "cancelled" ||
      state.selectedJob?.status !== selectedFromList.status ||
      state.selectedJob?.destination_status !== selectedFromList.destination_status ||
      state.selectedJob?.destination_progress !== selectedFromList.destination_progress ||
      state.selectedJob?.updated_at !== selectedFromList.updated_at;

    if (shouldRefreshDetails) {
      await selectJob(state.selectedJobId);
    }
  }, JOBS_POLL_MS);

  state.systemPollTimer = setInterval(async () => {
    await loadSystemInfo();
  }, JOBS_POLL_MS);
}

function bindPublicEvents() {
  if (publicEventsBound) return;
  publicEventsBound = true;

  document.getElementById("language-switch")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-lang]");
    if (!button) return;

    const lang = button.dataset.lang;
    if (!lang || lang === state.language) return;

    closeNavDrawer();

    state.language = lang;
    localStorage.setItem("link2nas_language", lang);

    if (state.currentUser) {
      await rerenderAppForLanguageChange();
      return;
    }

    renderStaticTexts();

    const setupStatus = await getSetupStatus();
    if (setupStatus.setup_required) {
      renderSetupForm();
    } else {
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
    }

    bindAuthEvents();
  });
}


async function bootstrap() {
  applyTheme(localStorage.getItem("link2nas_theme") || "auto");

  const savedLanguage = localStorage.getItem("link2nas_language");

  if (savedLanguage) {
    state.language = savedLanguage;
  }

  renderStaticTexts();
  bindPublicEvents();
  resetInactivityTimer();
  updateAuthVisibility();
  hideAdminIfNeeded();

  const handledPublicRoute = await handlePublicAccountRoute();
  if (handledPublicRoute) {
    return;
  }

  const existingToken = localStorage.getItem("link2nas_token");

  /*
   * Important:
   * - En multi-user sans token, /api/v2/me répond 401.
   * - En single-user, /api/v2/me retourne directement le user interne.
   * Donc on tente /me avant de rendre login/setup.
   */
  try {
    state.currentUser = await getMe();

    applyCurrentUserTheme(state.currentUser);

    if (state.currentUser?.single_user_mode) {
      localStorage.removeItem("link2nas_token");
      state.activeAdminTab = state.activeAdminTab === "users"
        ? "maintenance"
        : state.activeAdminTab;
    }

    updateAuthVisibility();

    if (state.currentUser?.force_password_change) {
      renderForcedPasswordChangeForm();
      bindAuthEvents();
      showAppMessage(t("messages.must_change_password"), "info");
      return;
    }

    hideAdminIfNeeded();

    await enterMainApplication({ useHomePage: true });

    if (state.activePage === "admin") {
      await loadAdmin();
    }

    return;
  } catch {
    if (existingToken) {
      localStorage.removeItem("link2nas_token");
    }
  }

  const setupStatus = await getSetupStatus();

  if (setupStatus.setup_required) {
    renderSetupForm();
    bindAuthEvents();
    return;
  }

  let appInfoEmailAvailable = true;
  try {
    const appInfo = await getPublicAppInfo();
    state.appInfo = appInfo;
    appInfoEmailAvailable = appInfo?.email_sending_available ?? true;
  } catch {
    // Non bloquant — on affiche le bouton magic login par défaut
  }

  renderLoginForm(appInfoEmailAvailable);
  bindAuthEvents();
}

function showBatchResultPanel(results) {
  document.getElementById("batch-result-panel")?.remove();

  const okCount = results.filter((r) => r.ok).length;

  const panel = document.createElement("div");
  panel.id = "batch-result-panel";
  panel.className = "batch-result-panel";

  const title = document.createElement("div");
  title.className = "batch-result-title";
  title.textContent = t("batch.result_title");
  panel.appendChild(title);

  const list = document.createElement("ul");
  list.className = "batch-result-list";
  for (const item of results) {
    const li = document.createElement("li");
    li.className = `batch-result-item ${item.ok ? "is-ok" : "is-error"}`;

    const name = document.createElement("span");
    name.className = "batch-result-filename";
    name.textContent = `${item.ok ? "✓" : "✗"} ${item.filename}`;
    li.appendChild(name);

    if (item.ok && item.reused) {
      const note = document.createElement("span");
      note.className = "batch-result-error";
      note.textContent = t("batch.job_reused");
      li.appendChild(note);
    }

    if (!item.ok && item.error) {
      const err = document.createElement("span");
      err.className = "batch-result-error";
      err.textContent = item.error;
      li.appendChild(err);
    }

    list.appendChild(li);
  }
  panel.appendChild(list);

  const actions = document.createElement("div");
  actions.className = "batch-result-actions";

  if (okCount > 0) {
    const viewBtn = document.createElement("button");
    viewBtn.type = "button";
    viewBtn.className = "btn btn-primary";
    viewBtn.textContent = t("batch.view_jobs");
    viewBtn.addEventListener("click", () => {
      panel.remove();
      setActivePage("jobs");
    });
    actions.appendChild(viewBtn);
  }

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "btn";
  closeBtn.textContent = t("batch.close");
  closeBtn.addEventListener("click", () => panel.remove());
  actions.appendChild(closeBtn);

  panel.appendChild(actions);
  const inlineContainer = document.getElementById("create-job-result-panel");
  if (inlineContainer) {
    panel.classList.add("is-inline");
    inlineContainer.innerHTML = "";
    inlineContainer.appendChild(panel);
  } else {
    document.body.appendChild(panel);
  }
}

initNavigation({
  bindGlobalEvents,
  bindBannerEvents,
  startPolling,
  renderAnnouncementBanner,
  pickBannerAnnouncement,
  updateAnnouncementBadge,
  loadAnnouncements,
});

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

bootstrap().catch((error) => {
  console.error(error);
});