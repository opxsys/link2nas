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
  createFirstAdmin,
  login,
  getMe,
  logout,

  updateMe,
  changeMyPassword,
  requestEmailVerification,
  getMyIntegrationSettings,
  saveMyIntegrationSettings,
  listUserApiKeys,
  createUserApiKey,
  revokeUserApiKey,
  deleteUserApiKey,

  listProviders,
  saveProvider,
  deleteProvider,
  testProvider,
  listDestinations,
  saveDestination,
  deleteDestination,
  testDestination,

  testProviderFromSettings,
  testDestinationFromSettings,
  testNotificationConfig,
  listNotificationConfigs,
  createNotificationConfig,
  updateNotificationConfig,
  deleteNotificationConfig,
  testStoredNotificationConfig,
  listNotificationRules,
  createNotificationRule,
  updateNotificationRule,
  deleteNotificationRule,
  listUsers,
  createUser,
  updateUser,
  disableUser,
  enableUser,
  verifyUserEmail,
  resetUserPassword,
  createUserInvitation,
  createUserPasswordResetLink,
  sendUserInvitationEmail,
  sendUserPasswordResetEmail,
  deleteUser,
  getPublicTokenStatus,
  acceptInvitation,
  confirmPasswordReset,
  getAdminSmtpSettings,
  getAdminSecuritySettings,
  saveAdminSecuritySettings,
  getAdminCleanupSettings,
  saveAdminCleanupSettings,
  runAdminCleanup,
  getAdminMaintenanceStatus,
  saveAdminSmtpSettings,
  testAdminSmtpSettings,
  requestMagicLogin,
  confirmMagicLogin,
  confirmEmailVerification,
  getAdminRestartCooldowns,
  saveAdminRestartCooldowns,
  getAdminRuntimeSettings,
  saveAdminRuntimeSettings,
  getAdminNotificationDispatcherStatus,
  runAdminNotificationDispatcherOnce,
  getAdminGeneralSettings,
  saveAdminGeneralSettings,
  getPublicAppInfo,
  listActiveAnnouncements,
  openAnnouncement,
  readAnnouncement,
  acknowledgeAnnouncement,
  listAdminAnnouncements,
  createAdminAnnouncement,
  updateAdminAnnouncement,
  deleteAdminAnnouncement,
  getAdminAnnouncementTracking,
  getEmailTemplate,
  saveEmailTemplate,
  previewEmailTemplate,
  resetEmailTemplate,
  getAdminAntiAbuse,
  resetAdminAntiAbuseAll,
  resetAdminAntiAbuseKind,
  getMyPublicSpace,
  cleanMyPublicSpace,
} from "./api.js";

import {
  renderSetupForm,
  renderLoginForm,
  renderAcceptInvitationForm,
  renderPasswordResetForm,
  renderInvalidToken,
  renderForcedPasswordChangeForm,
  showMainApp,
  renderMagicLoginRequestForm,
  renderMagicLoginProcessing,
  renderEmailVerificationProcessing,
} from "./render/auth.js";

import {
  renderProvidersPanel,
  renderDestinationsPanel,
  updateDestinationFields,
  fillProviderForm,
  fillDestinationForm,
  renderSettingsPanel,
  renderEspaceContent,
  updateNotificationChannelFields,
  fillNotificationChannelForm,
  resetNotificationChannelForm,
  fillNotificationRuleForm,
  resetNotificationRuleForm,
} from "./render/settings.js";

import { renderUsersPanel, renderUserCardList, renderAnnouncementsAdminPanel, renderAnnouncementTrackingPanel, renderAnnouncementForm, renderAntiAbuseSection } from "./render/admin.js";
import { renderAnnouncementsPage } from "./render/announcements.js";
import { renderProwlarrPanel, hasConfiguredProwlarr } from "./render/prowlarr.js";
import {
  showConfirmModal,
  showLinkModal,
  showSecretModal,
  escapeForModalHtml,
} from "./ui/modals.js";

let inactivityTimer;
let publicEventsBound = false;
let globalEventsBound = false;
const DEFAULT_SESSION_INACTIVITY_MINUTES = 30;



function showApiKeyFeedback(message, type = "info") {
  const el = document.getElementById("api-key-feedback");
  if (!el) { showAppMessage(message, type); return; }
  el.textContent = message;
  el.className = `api-key-feedback api-key-feedback-${type}`;
  el.hidden = false;
}

function showProviderFeedback(message, type = "info") {
  const el = document.getElementById("provider-feedback");
  if (!el) { showAppMessage(message, type); return; }
  el.textContent = message;
  el.className = `provider-feedback provider-feedback-${type}`;
  el.hidden = false;
}

function showDestinationFeedback(message, type = "info") {
  const el = document.getElementById("destination-feedback");
  if (!el) { showAppMessage(message, type); return; }
  el.textContent = message;
  el.className = `destination-feedback destination-feedback-${type}`;
  el.hidden = false;
}

function showNotificationFeedback(message, type = "info") {
  const el = document.getElementById("notification-feedback");
  if (!el) { showAppMessage(message, type); return; }
  el.textContent = message;
  el.className = `notification-feedback notification-feedback-${type}`;
  el.hidden = false;
}

function showAdminFeedback(section, message, type = "info") {
  const el = document.getElementById(`admin-${section}-feedback`);
  if (!el) { showAppMessage(message, type); return; }
  el.textContent = message;
  el.className = `admin-feedback admin-feedback-${type}`;
  el.hidden = false;
}

function buildDestinationConfigJsonFromState(dest) {
  const cfg = dest.config || {};
  const type = dest.destination_type || dest.destination_name;

  if (type === "synology") {
    return JSON.stringify({
      synology_url: cfg.synology_url || "",
      username: cfg.username || "",
      destination_base: cfg.destination_base || "",
      verify_ssl: cfg.verify_ssl ?? true,
    });
  }

  return JSON.stringify({
    base_path: cfg.base_path || "downloads",
  });
}


function getPublicTokenFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return String(params.get("token") || "").trim();
}

function isInviteRoute() {
  return window.location.pathname === "/invite";
}

function isPasswordResetRoute() {
  return window.location.pathname === "/reset-password";
}

function isMagicLoginRoute() {
  return window.location.pathname === "/magic-login";
}

function isEmailVerificationRoute() {
  return window.location.pathname === "/verify-email";
}

function clearPublicAccountUrl() {
  window.history.replaceState({}, "", "/");
}

function validatePasswordConfirmation(form) {
  const password = String(form.password?.value || "");
  const passwordConfirm = String(form.password_confirm?.value || "");

  if (password.length < 8) {
    showAppMessage(t("auth.error.password_too_short"), "error");
    return null;
  }

  if (password !== passwordConfirm) {
    showAppMessage(t("auth.error.passwords_mismatch"), "error");
    return null;
  }

  return password;
}


function validateForcedPasswordChangeForm(form) {
  const currentPassword = String(form.current_password?.value || "");
  const newPassword = String(form.new_password?.value || "");
  const newPasswordConfirm = String(form.new_password_confirm?.value || "");

  if (!currentPassword) {
    showAppMessage(t("auth.error.temp_password_required"), "error");
    return null;
  }

  if (newPassword.length < 8) {
    showAppMessage(t("auth.error.new_password_too_short"), "error");
    return null;
  }

  if (newPassword !== newPasswordConfirm) {
    showAppMessage(t("auth.error.new_passwords_mismatch"), "error");
    return null;
  }

  if (currentPassword === newPassword) {
    showAppMessage(t("auth.error.new_password_same_as_temp"), "error");
    return null;
  }

  return {
    current_password: currentPassword,
    new_password: newPassword,
  };
}

async function enterMainApplication({ useHomePage = false } = {}) {
  showMainApp();
  renderJobDetails(null);
  bindGlobalEvents();
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

function hideAdminIfNeeded() {
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

function updateAuthVisibility() {
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

let _themeMediaListener = null;

function applyCurrentUserTheme(user) {
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

function openNavDrawer() {
  const drawer = document.getElementById("nav-drawer");
  const overlay = document.getElementById("nav-drawer-overlay");
  const burgerBtn = document.getElementById("nav-burger-btn");

  if (drawer) drawer.classList.add("is-open");
  if (overlay) overlay.classList.add("is-open");
  if (burgerBtn) burgerBtn.setAttribute("aria-expanded", "true");
}

function closeNavDrawer() {
  const drawer = document.getElementById("nav-drawer");
  const overlay = document.getElementById("nav-drawer-overlay");
  const burgerBtn = document.getElementById("nav-burger-btn");

  if (drawer) drawer.classList.remove("is-open");
  if (overlay) overlay.classList.remove("is-open");
  if (burgerBtn) burgerBtn.setAttribute("aria-expanded", "false");
}

function updateProwlarrNavVisibility() {
  const prowlarrButton = document.querySelector('[data-page="prowlarr"]');
  if (!prowlarrButton) return;

  prowlarrButton.hidden = !hasConfiguredProwlarr();
}

function resolveHomePage() {
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

function setActivePage(page, persist = true) {
  const target = page || "jobs";

  state.activePage = target;

  if (persist) {
    localStorage.setItem("link2nas_active_page", target);
  }

  renderPageVisibility();
}

function renderPageVisibility() {
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

function renderStaticTexts() {
  // TODO: expose a public endpoint (no auth) to apply app_name/tagline before login
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

async function rerenderAppForLanguageChange() {
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

async function loadSettings() {
  const [
    providers,
    destinations,
    me,
    notificationConfigs,
    notificationRules,
    apiKeys,
    integrationSettings,
  ] = await Promise.all([
    listProviders(),
    listDestinations(),
    getMe(),
    listNotificationConfigs(),
    listNotificationRules(),
    listUserApiKeys(),
    getMyIntegrationSettings(),
  ]);

  state.providers = providers;
  state.destinations = destinations;
  state.currentUser = me;
  applyCurrentUserTheme(me);
  state.notificationConfigs = notificationConfigs;
  state.notificationRules = notificationRules;
  state.userApiKeys = apiKeys;
  state.integrationSettings = integrationSettings;

  const settingsData = {
    providers,
    destinations,
    notificationConfigs,
    notificationRules,
    apiKeys,
    integrationSettings,
  };

  if (typeof renderSettingsPanel === "function") {
    renderSettingsPanel(settingsData, me);
  } else {
    renderProvidersPanel(providers);
    renderDestinationsPanel(destinations);
  }

  const settingsContainer = document.getElementById("settings-panel");
  if (settingsContainer) {
    settingsContainer.removeEventListener("settings-tab-change", onSettingsTabChange);
    settingsContainer.addEventListener("settings-tab-change", onSettingsTabChange);
  }

  const activeTab = localStorage.getItem("settings_tab");
  if (activeTab === "espace") {
    await loadEspace();
  }

  renderCreateJobForm();
  updateProwlarrNavVisibility();

  if (state.activePage === "prowlarr") {
    renderProwlarrPanel();
  }

  await loadAndRenderBanner();
}

function getFilteredAdminUsers(users, query, filter) {
  const q = (query || "").toLowerCase().trim();
  const now = new Date();

  return users.filter((u) => {
    if (q) {
      const matchText =
        (u.email || "").toLowerCase().includes(q) ||
        (u.display_name || "").toLowerCase().includes(q) ||
        (u.role || "").toLowerCase().includes(q);
      if (!matchText) return false;
    }

    switch (filter) {
      case "active":           return Boolean(u.is_active);
      case "disabled":         return !u.is_active;
      case "super-admin":      return Boolean(u.is_super_admin);
      case "email-unverified": return !u.email_verified;
      case "expired":          return Boolean(u.account_expires_at) && new Date(u.account_expires_at) < now;
      default:                 return true;
    }
  });
}

function bindAdminUsersFilters() {
  const search = document.getElementById("admin-users-search");
  const chips  = document.querySelectorAll("[data-admin-users-filter]");
  const list   = document.querySelector('[data-admin-panel="users"] .admin-users-list');
  const badge  = document.querySelector('[data-admin-panel="users"] .admin-section-title .badge');
  if (!search || !list) return;

  function applyFilter() {
    const query  = search.value;
    const active = document.querySelector("[data-admin-users-filter].is-active");
    const filter = active?.dataset.adminUsersFilter || "all";
    const filtered = getFilteredAdminUsers(state.users || [], query, filter);
    const emailAvail = !!(state.smtpSettings?.enabled && state.smtpSettings?.host && state.smtpSettings?.port && state.smtpSettings?.from_email);

    list.innerHTML = filtered.length
      ? renderUserCardList(filtered, emailAvail)
      : `<div class="empty-state">${t("admin.users.empty_filtered")}</div>`;

    if (badge) {
      badge.textContent = `${filtered.length} ${filtered.length > 1 ? t("admin.users.count_plural") : t("admin.users.count_singular")}`;
    }
  }

  search.addEventListener("input", applyFilter);

  chips.forEach((chip) => {
    chip.addEventListener("click", () => {
      chips.forEach((c) => c.classList.remove("is-active"));
      chip.classList.add("is-active");
      applyFilter();
    });
  });
}

async function onSettingsTabChange(event) {
  if (event.detail?.tab === "espace") {
    await loadEspace();
  }
}

async function loadEspace() {
  const contentEl = document.getElementById("espace-content");
  if (!contentEl) return;

  try {
    const data = await getMyPublicSpace();
    contentEl.innerHTML = renderEspaceContent(data);

    const copyBtn = contentEl.querySelector("#espace-copy-btn");
    if (copyBtn) {
      copyBtn.addEventListener("click", async () => {
        const url = copyBtn.dataset.url || "";
        try {
          await navigator.clipboard.writeText(url);
          copyBtn.textContent = "✓";
          setTimeout(() => { copyBtn.textContent = "⧉"; }, 2000);
        } catch {
          // clipboard not available
        }
      });
    }

    const cleanupBtn = contentEl.querySelector("#espace-cleanup-btn");
    if (cleanupBtn) {
      cleanupBtn.addEventListener("click", async () => {
        const ok = await showConfirmModal({
          title: t("settings.espace.cleanup_confirm_title"),
          message: t("settings.espace.cleanup_confirm"),
          confirmLabel: t("settings.espace.cleanup_btn"),
          cancelLabel: t("common.cancel"),
          danger: true,
        });
        if (!ok) return;
        const feedbackEl = contentEl.querySelector("#espace-feedback");
        try {
          cleanupBtn.disabled = true;
          const result = await cleanMyPublicSpace();
          if (feedbackEl) {
            feedbackEl.hidden = false;
            feedbackEl.className = "form-feedback success";
            feedbackEl.textContent = t("settings.espace.cleanup_ok").replace("{count}", result.deleted_count ?? 0);
          }
          await loadEspace();
        } catch (err) {
          if (feedbackEl) {
            feedbackEl.hidden = false;
            feedbackEl.className = "form-feedback error";
            feedbackEl.textContent = t("settings.espace.cleanup_error");
          }
        } finally {
          if (cleanupBtn) cleanupBtn.disabled = false;
        }
      });
    }
  } catch {
    if (contentEl) {
      contentEl.innerHTML = `<p class="muted">${t("settings.espace.error")}</p>`;
    }
  }
}

async function loadAntiAbuseSection() {
  const contentEl = document.getElementById("admin-anti-abuse-content");
  const feedbackEl = document.getElementById("admin-anti-abuse-feedback");
  if (!contentEl) return;

  try {
    const data = await getAdminAntiAbuse();
    state.antiAbuseData = data;
    contentEl.innerHTML = renderAntiAbuseSection(data);
    if (feedbackEl) feedbackEl.hidden = true;
  } catch (error) {
    showAdminFeedback("anti-abuse", error.message || t("messages.admin_action_error"), "error");
  }
}

async function loadAdmin() {
  const isSingleUserMode = Boolean(state.currentUser?.single_user_mode);

  const [
    users,
    smtpSettings,
    securitySettings,
    cleanupSettings,
    maintenanceStatus,
    timeoutSettings,
    runtimeSettings,
    generalSettings,
    adminAnnouncements,
  ] = await Promise.all([
    isSingleUserMode ? Promise.resolve([]) : listUsers(),
    getAdminSmtpSettings(),
    getAdminSecuritySettings(),
    getAdminCleanupSettings(),
    getAdminMaintenanceStatus(),
    getAdminRestartCooldowns(),
    getAdminRuntimeSettings(),
    getAdminGeneralSettings(),
    listAdminAnnouncements(),
  ]);

  state.runtimeSettings = runtimeSettings;
  state.users = users;
  state.smtpSettings = smtpSettings;
  state.securitySettings = securitySettings;
  state.cleanupSettings = cleanupSettings;
  state.maintenanceStatus = maintenanceStatus;
  state.timeoutSettings = timeoutSettings;
  state.restartCooldowns = timeoutSettings;
  state.generalSettings = generalSettings;
  state.adminAnnouncements = Array.isArray(adminAnnouncements) ? adminAnnouncements : [];

  const emailAvailable = !!(smtpSettings?.enabled && smtpSettings?.host && smtpSettings?.port && smtpSettings?.from_email);

  renderUsersPanel(
    users,
    smtpSettings,
    securitySettings,
    cleanupSettings,
    maintenanceStatus,
    timeoutSettings,
    runtimeSettings,
    {
      singleUserMode: isSingleUserMode,
      emailAvailable,
    },
    generalSettings,
    state.adminAnnouncements
  );

  if (!isSingleUserMode) {
    updateUserCreationModeFields();
    bindAdminUsersFilters();
  }

  const defaultAdminTab = isSingleUserMode ? "maintenance" : "users";

  if (isSingleUserMode && state.activeAdminTab === "users") {
    state.activeAdminTab = defaultAdminTab;
  }

  const resolvedAdminTab = state.activeAdminTab || defaultAdminTab;
  switchAdminTab(resolvedAdminTab);
  renderStaticTexts();

  if (resolvedAdminTab === "email-templates") {
    await initEmailTemplatesPanel();
  }

  if (resolvedAdminTab === "security") {
    await loadAntiAbuseSection();
  }
}

function switchAdminTab(tabName) {
  const fallbackTab = state.currentUser?.single_user_mode ? "maintenance" : "users";
  const selectedTab = String(tabName || fallbackTab).trim();

  document.querySelectorAll("[data-admin-tab]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.adminTab === selectedTab);
  });

  document.querySelectorAll("[data-admin-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.adminPanel !== selectedTab;
  });
}

function buildDestinationConfig(form) {
  const destinationType = form.destination_type?.value || form.destination_name?.value;

  if (destinationType === "local") {
    return {
      base_path: form.base_path.value,
    };
  }

  return {
    synology_url: form.synology_url.value,
    username: form.username.value,
    password: form.password.value,
    verify_ssl: Boolean(form.verify_ssl.checked),
    destination_base: form.destination_base.value,
  };
}

function getOptionalDatetimeValue(form, name) {
  const value = form[name]?.value;
  return value ? value : null;
}

function buildSmtpSettingsPayload(form) {
  return {
    enabled: Boolean(form.enabled?.checked),
    host: form.host?.value || "",
    port: Number(form.port?.value || 587),
    username: form.username?.value || "",
    password: form.password?.value || undefined,
    from_email: form.from_email?.value || "",
    from_name: form.from_name?.value || "",
    use_tls: Boolean(form.use_tls?.checked),
    use_ssl: Boolean(form.use_ssl?.checked),
  };
}

function buildSecuritySettingsPayload(form) {
  return {
    token_ttl: {
      invitation_ttl_hours: Number(form.invitation_ttl_hours?.value || 48),
      password_reset_ttl_hours: Number(form.password_reset_ttl_hours?.value || 2),
      magic_login_ttl_minutes: Number(form.magic_login_ttl_minutes?.value || 15),
      email_verification_ttl_hours: Number(form.email_verification_ttl_hours?.value || 24),
      session_inactivity_minutes: Number(form.session_inactivity_minutes?.value || 30),
    },
    password_policy: {
      min_length: Number(form.min_length?.value || 10),
      require_uppercase: Boolean(form.require_uppercase?.checked),
      require_lowercase: Boolean(form.require_lowercase?.checked),
      require_number: Boolean(form.require_number?.checked),
      require_special: Boolean(form.require_special?.checked),
    },
  };
}

function buildCleanupSettingsPayload(form) {
  return {
    retention: {
      torrent_tmp_days: Number(form.torrent_tmp_days?.value || 7),
      completed_jobs_days: Number(form.completed_jobs_days?.value || 30),
      failed_jobs_days: Number(form.failed_jobs_days?.value || 30),
      cancelled_jobs_days: Number(form.cancelled_jobs_days?.value || 15),
      expired_tokens_days: Number(form.expired_tokens_days?.value || 7),
    },
  };
}

function buildRestartCooldownsPayload(form) {
  return {
    default_seconds: Number(form.default_seconds?.value || 10),
    realdebrid_seconds: Number(form.realdebrid_seconds?.value || 60),
    alldebrid_seconds: Number(form.alldebrid_seconds?.value || 8),
  };
}

function buildRuntimeSettingsPayload(form) {
  return {
    notifications: {
      dispatcher: {
        enabled: Boolean(form.notification_dispatcher_enabled?.checked),
        interval_seconds: Number(form.notification_dispatcher_interval_seconds?.value || 60),
        limit: Number(form.notification_dispatcher_limit?.value || 25),
      },
    },
    jobs: {
      orchestrator: {
        enabled: Boolean(form.jobs_orchestrator_enabled?.checked),
        interval_seconds: Number(form.jobs_orchestrator_interval_seconds?.value || 5),
        max_jobs_per_run: Number(form.jobs_orchestrator_max_jobs_per_run?.value || 25),
        auto_refresh_enabled: Boolean(form.jobs_orchestrator_auto_refresh_enabled?.checked),
        auto_unrestrict_enabled: Boolean(form.jobs_orchestrator_auto_unrestrict_enabled?.checked),
        auto_send_destination_enabled: Boolean(form.jobs_orchestrator_auto_send_destination_enabled?.checked),
      },
    },
    downloads: {
      local_worker: {
        enabled: Boolean(form.local_worker_enabled?.checked),
        poll_interval_seconds: Number(form.local_worker_poll_interval_seconds?.value || 5),
        max_concurrent_downloads: Number(form.local_worker_max_concurrent_downloads?.value || 1),
      },
    },
  };
}
function buildNotificationChannelPayload(form) {
  const channel = String(form.channel?.value || "").trim().toLowerCase();

  const payload = {
    name: String(form.name?.value || "").trim(),
    channel,
    is_enabled: Boolean(form.is_enabled?.checked),
    is_default: Boolean(form.is_default?.checked),
    config: {},
  };

  if (channel === "email") {
    const toEmail = String(form.to_email?.value || "").trim();

    if (toEmail) {
      payload.config.to_email = toEmail;
    }

    return payload;
  }

  if (channel === "gotify") {
    payload.config.server_url = String(form.gotify_server_url?.value || "").trim();

    const token = String(form.gotify_token?.value || "").trim();
    if (token) {
      payload.config.token = token;
    }

    return payload;
  }

  if (channel === "webhook") {
    payload.config.url = String(form.webhook_url?.value || "").trim();
    payload.config.method = String(form.webhook_method?.value || "POST").trim().toUpperCase();

    const headersRaw = String(form.webhook_headers?.value || "").trim();

    if (headersRaw) {
      payload.config.headers = JSON.parse(headersRaw);
    }

    return payload;
  }

  return payload;
}

function buildNotificationRulePayload(form) {
  const eventTypes = Array.from(form.querySelectorAll("input[name='event_type']:checked"))
    .map((input) => input.value)
    .filter(Boolean);

  return {
    name: String(form.name?.value || "").trim(),
    config_id: String(form.config_id?.value || "").trim(),
    is_enabled: Boolean(form.is_enabled?.checked),
    severity_min: String(form.severity_min?.value || "error").trim(),
    event_types: eventTypes,
    rate_limit_per_hour: Number(form.rate_limit_per_hour?.value || 30),
    scope: "user",
  };
}

function updateUserCreationModeFields() {
  const form = document.getElementById("user-form");
  if (!form) return;

  const mode = form.creation_mode?.value || "password";
  const passwordRow = document.getElementById("user-password-row");
  const forcePasswordChangeRow = document.getElementById("user-force-password-change-row");
  const passwordInput = form.password;

  const isInvitation = mode === "invitation";

  if (passwordRow) {
    passwordRow.hidden = isInvitation;
  }

  if (forcePasswordChangeRow) {
    forcePasswordChangeRow.hidden = isInvitation;
  }

  if (passwordInput) {
    passwordInput.required = !isInvitation;

    if (isInvitation) {
      passwordInput.value = "";
    }
  }
}

async function handleSettingsSubmit(form) {
  if (form.id === "prowlarr-settings-form") {
    const saved = await saveMyIntegrationSettings({
      prowlarr_enabled: Boolean(form.prowlarr_enabled?.checked),
      prowlarr_url: form.prowlarr_url?.value || "",
      prowlarr_open_mode: form.prowlarr_open_mode?.value || "both",
      home_page: form.home_page?.value || "jobs",
    });

    state.integrationSettings = saved;

    if (state.activePage === "prowlarr" && !hasConfiguredProwlarr()) {
      state.activePage = "jobs";
      localStorage.setItem("link2nas_active_page", "jobs");
    }

    showAppMessage(t("messages.settings_prowlarr_saved"), "success");
    await loadSettings();
    renderPageVisibility();
    return;
  }

  if (form.id === "provider-form") {
    try {
      await saveProvider({
        provider_config_id: form.provider_config_id?.value || undefined,
        name: form.elements.name?.value || "",
        provider_type: form.provider_type.value,
        api_key: form.api_key.value || undefined,
        is_enabled: Boolean(form.is_enabled.checked),
        is_default: Boolean(form.is_default.checked),
      });

      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_saved"), "success");
    } catch (error) {
      showProviderFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (form.id === "destination-form") {

    const config = buildDestinationConfig(form);

    try {
      await saveDestination({
        destination_config_id: form.destination_config_id?.value || undefined,
        name: form.elements.name?.value || "",
        destination_type: form.destination_type.value,
        config_json: JSON.stringify(config),
        is_enabled: Boolean(form.is_enabled.checked),
        is_default: Boolean(form.is_default.checked),
      });
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_saved"), "success");
    } catch (err) {
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (form.id === "my-profile-form") {
    const previousEmail = String(state.currentUser?.email || "").trim().toLowerCase();
    const newEmail = String(form.email.value || "").trim().toLowerCase();

    const me = await updateMe({
      email: form.email.value,
      display_name: form.display_name.value,
      preferred_language: form.preferred_language.value,
      receive_application_emails: Boolean(form.receive_application_emails?.checked),
      ui_theme: form.ui_theme?.value || "auto",
    });

    state.currentUser = me;
    applyCurrentUserTheme(me);

    if (newEmail && previousEmail && newEmail !== previousEmail) {
      showAppMessage(
        t("messages.settings_profile_updated_email"),
        "info"
      );
    } else {
      showAppMessage(t("messages.settings_profile_updated"), "success");
    }

    await loadSettings();
    return;
  }

  if (form.id === "change-password-form") {
    await changeMyPassword({
      current_password: form.current_password.value,
      new_password: form.new_password.value,
    });

    form.reset();
    showAppMessage(t("messages.settings_password_changed"), "success");
    return;
  }

  if (form.id === "api-key-form") {
    const scopes = Array.from(form.querySelectorAll("input[name='scope']:checked"))
      .map((input) => input.value)
      .filter(Boolean);

    try {
      const result = await createUserApiKey({
        name: form.name.value,
        scopes,
      });

      form.reset();

      await showSecretModal({
        title: t("settings.api_keys.modal_title"),
        message: t("settings.api_keys.modal_message"),
        secret: result.key,
        copyLabel: t("settings.api_keys.modal_copy"),
        closeLabel: t("common.close"),
      });
      await loadSettings();
    } catch (error) {
      showApiKeyFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (form.id === "test-gotify-form") {
    const result = await testNotificationConfig({
      channel: "gotify",
      config: {
        server_url: form.server_url.value,
        token: form.token.value,
      },
    });

    showAppMessage(result.message || t("messages.settings_channel_test_ok"), "success");
    return;
  }

  if (form.id === "test-webhook-form") {
    const result = await testNotificationConfig({
      channel: "webhook",
      config: {
        url: form.url.value,
        method: "POST",
      },
    });

    showAppMessage(result.message || t("messages.settings_channel_test_ok"), "success");
    return;
  }

  if (form.id === "notification-channel-form") {
    const configId = String(form.config_id?.value || "").trim();
    const payload = buildNotificationChannelPayload(form);

    try {
      if (configId) {
        await updateNotificationConfig(configId, payload);
        await loadSettings();
        showNotificationFeedback(t("messages.settings_channel_updated"), "success");
      } else {
        await createNotificationConfig(payload);
        await loadSettings();
        showNotificationFeedback(t("messages.settings_channel_created"), "success");
      }
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (form.id === "notification-rule-form") {
    const ruleId = String(form.rule_id?.value || "").trim();
    const payload = buildNotificationRulePayload(form);

    if (!payload.config_id) {
      showNotificationFeedback(t("messages.select_notification_channel"), "error");
      return;
    }

    try {
      if (ruleId) {
        await updateNotificationRule(ruleId, payload);
        await loadSettings();
        showNotificationFeedback(t("messages.settings_rule_updated"), "success");
      } else {
        await createNotificationRule(payload);
        await loadSettings();
        showNotificationFeedback(t("messages.settings_rule_created"), "success");
      }
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }
}

async function handleSettingsClick(button) {
  const action = button.dataset.settingsAction || button.dataset.action;

  if (action === "edit-provider") {
    const provider = state.providers.find((p) => p.id === button.dataset.providerId);
    fillProviderForm(provider);
    return;
  }

  if (action === "cancel-provider-edit") {
    const form = document.getElementById("provider-form");
    if (!form) return;
    form.reset();
    form.provider_config_id.value = "";
    form.querySelector("button[type='submit']").textContent = t("settings.providers.save");
    button.hidden = true;
    return;
  }

  if (action === "toggle-destination-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const dest = state.destinations.find((d) => d.id === button.dataset.destinationId);
    if (!dest) { button.disabled = false; return; }
    const payload = {
      destination_config_id: dest.id,
      destination_type: dest.destination_type || dest.destination_name,
      name: dest.name,
      config_json: buildDestinationConfigJsonFromState(dest),
      is_enabled: newEnabled,
      is_default: newEnabled ? dest.is_default : false,
    };
    try {
      await saveDestination(payload);
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_enabled_updated"), "success");
    } catch (err) {
      await loadSettings();
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "set-destination-default") {
    if (!button.checked) { button.checked = true; return; }
    button.disabled = true;
    const dest = state.destinations.find((d) => d.id === button.dataset.destinationId);
    if (!dest) { button.disabled = false; return; }
    const payload = {
      destination_config_id: dest.id,
      destination_type: dest.destination_type || dest.destination_name,
      name: dest.name,
      config_json: buildDestinationConfigJsonFromState(dest),
      is_enabled: true,
      is_default: true,
    };
    try {
      await saveDestination(payload);
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_default_updated"), "success");
    } catch (err) {
      await loadSettings();
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "cancel-destination-edit") {
    const form = document.getElementById("destination-form");
    if (!form) return;
    form.reset();
    form.destination_config_id.value = "";
    form.querySelector("button[type='submit']").textContent = t("settings.destinations.save");
    button.hidden = true;
    updateDestinationFields();
    return;
  }

  if (action === "edit-destination") {
    const destination = state.destinations.find((d) => d.id === button.dataset.destinationId);
    fillDestinationForm(destination);
    return;
  }

  if (action === "test-destination") {
    try {
      const result = await testDestination(button.dataset.destinationId);
      await loadSettings();
      showDestinationFeedback(result.message || t("messages.settings_destination_tested"), "success");
    } catch (err) {
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "toggle-provider-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const payload = {
      provider_config_id: button.dataset.providerId,
      provider_type: button.dataset.providerType,
      name: button.dataset.providerName,
      is_enabled: newEnabled,
      is_default: newEnabled ? button.dataset.isDefault === "1" : false,
    };
    try {
      await saveProvider(payload);
      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_enabled_updated"), "success");
    } catch (err) {
      await loadSettings();
      showProviderFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "set-provider-default") {
    if (!button.checked) {
      button.checked = true;
      return;
    }
    button.disabled = true;
    const payload = {
      provider_config_id: button.dataset.providerId,
      provider_type: button.dataset.providerType,
      name: button.dataset.providerName,
      is_enabled: true,
      is_default: true,
    };
    try {
      await saveProvider(payload);
      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_default_updated"), "success");
    } catch (err) {
      await loadSettings();
      showProviderFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "test-provider") {
    const providerId = button.dataset.providerId;
    try {
      const result = await testProvider(providerId);
      await loadSettings();
      const name = result.provider_user?.username || t("messages.settings_provider_tested_ok");
      showProviderFeedback(`${t("messages.settings_provider_tested")}: ${name}`, "success");
    } catch (error) {
      showProviderFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "delete-provider") {
    try {
      await deleteProvider(button.dataset.providerId);
      await loadSettings();
      showProviderFeedback(t("messages.settings_provider_deleted"), "success");
    } catch (error) {
      showProviderFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "delete-destination") {
    try {
      await deleteDestination(button.dataset.destinationId);
      await loadSettings();
      showDestinationFeedback(t("messages.settings_destination_deleted"), "success");
    } catch (err) {
      showDestinationFeedback(err.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "test-provider-settings") {
    const result = await testProviderFromSettings(button.dataset.providerId);
    showAppMessage(
      `Provider OK: ${result.provider_user?.username || "compte valide"}`,
      "success"
    );
    await loadSettings();
    return;
  }

  if (action === "test-destination-settings") {
    const result = await testDestinationFromSettings(button.dataset.destinationId);
    showAppMessage(result.message || t("messages.settings_destination_tested"), "success");
    return;
  }

  if (action === "reset-notification-channel-form") {
    resetNotificationChannelForm();
    return;
  }

  if (action === "reset-notification-rule-form") {
    resetNotificationRuleForm();
    return;
  }

  if (action === "show-prowlarr-api-key-modal") {
    const confirmed = await showConfirmModal({
      title: t("settings.prowlarr.no_qbt_key_modal_title"),
      message: t("settings.prowlarr.no_qbt_key_modal_message"),
      confirmLabel: t("settings.prowlarr.no_qbt_key_modal_goto"),
      cancelLabel: t("common.close"),
      danger: false,
    });
    if (confirmed) {
      document.querySelector('[data-settings-tab="api_keys"]')?.click();
    }
    return;
  }

  if (action === "cancel-notification-channel-edit") {
    resetNotificationChannelForm();
    button.hidden = true;
    return;
  }

  if (action === "cancel-notification-rule-edit") {
    resetNotificationRuleForm();
    button.hidden = true;
    return;
  }

  if (action === "toggle-notification-channel-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const cfg = state.notificationConfigs.find((c) => c.id === button.dataset.notificationConfigId);
    if (!cfg) { button.disabled = false; return; }
    try {
      await updateNotificationConfig(cfg.id, {
        is_enabled: newEnabled,
        is_default: newEnabled ? cfg.is_default : false,
      });
      await loadSettings();
      showNotificationFeedback(t("messages.settings_channel_enabled_updated"), "success");
    } catch (error) {
      await loadSettings();
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "set-notification-channel-default") {
    if (!button.checked) { button.checked = true; return; }
    button.disabled = true;
    const cfg = state.notificationConfigs.find((c) => c.id === button.dataset.notificationConfigId);
    if (!cfg) { button.disabled = false; return; }
    try {
      await updateNotificationConfig(cfg.id, { is_enabled: true, is_default: true });
      await loadSettings();
      showNotificationFeedback(t("messages.settings_channel_default_updated"), "success");
    } catch (error) {
      await loadSettings();
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "toggle-notification-rule-enabled") {
    button.disabled = true;
    const newEnabled = button.checked;
    const rule = state.notificationRules.find((r) => r.id === button.dataset.notificationRuleId);
    if (!rule) { button.disabled = false; return; }
    try {
      await updateNotificationRule(rule.id, { is_enabled: newEnabled });
      await loadSettings();
      showNotificationFeedback(t("messages.settings_rule_enabled_updated"), "success");
    } catch (error) {
      await loadSettings();
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "edit-notification-channel") {
    const configId = button.dataset.notificationConfigId;
    const config = state.notificationConfigs.find((item) => item.id === configId);

    if (!config) {
      showNotificationFeedback(t("messages.settings_channel_not_found"), "error");
      return;
    }

    fillNotificationChannelForm(config);
    return;
  }

  if (action === "test-stored-notification-channel") {
    const configId = button.dataset.notificationConfigId;

    if (!configId) return;

    try {
      const result = await testStoredNotificationConfig(configId);
      showNotificationFeedback(result.message || t("messages.settings_channel_test_ok"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "delete-notification-channel") {
    const configId = button.dataset.notificationConfigId;

    if (!configId) return;

    const confirmed = await showConfirmModal({
      title: t("settings.notifications.confirm_delete_channel_title"),
      message: t("settings.notifications.confirm_delete_channel_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await deleteNotificationConfig(configId);
      await loadSettings();
      showNotificationFeedback(t("messages.settings_channel_deleted"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "edit-notification-rule") {
    const ruleId = button.dataset.notificationRuleId;
    const rule = state.notificationRules.find((item) => item.id === ruleId);

    if (!rule) {
      showNotificationFeedback(t("messages.settings_rule_not_found"), "error");
      return;
    }

    fillNotificationRuleForm(rule);
    return;
  }

  if (action === "delete-notification-rule") {
    const ruleId = button.dataset.notificationRuleId;

    if (!ruleId) return;

    const confirmed = await showConfirmModal({
      title: t("settings.notifications.confirm_delete_rule_title"),
      message: t("settings.notifications.confirm_delete_rule_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await deleteNotificationRule(ruleId);
      await loadSettings();
      showNotificationFeedback(t("messages.settings_rule_deleted"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "test-notification-channel-form") {
    const form = document.getElementById("notification-channel-form");
    if (!form) return;

    const payload = buildNotificationChannelPayload(form);

    try {
      const result = await testNotificationConfig({
        channel: payload.channel,
        name: payload.name,
        config: payload.config,
      });
      showNotificationFeedback(result.message || t("messages.settings_channel_test_ok"), "success");
    } catch (error) {
      showNotificationFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "revoke-api-key") {
    const keyId = button.dataset.apiKeyId;

    if (!keyId) return;

    const confirmed = await showConfirmModal({
      title: t("settings.api_keys.confirm_revoke_title"),
      message: t("settings.api_keys.confirm_revoke_message"),
      confirmLabel: t("settings.api_keys.revoke"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await revokeUserApiKey(keyId);
      await loadSettings();
      showApiKeyFeedback(t("messages.settings_api_key_revoked"), "success");
    } catch (error) {
      showApiKeyFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

  if (action === "delete-api-key") {
    const keyId = button.dataset.apiKeyId;

    if (!keyId) return;

    const confirmed = await showConfirmModal({
      title: t("settings.api_keys.confirm_delete_title"),
      message: t("settings.api_keys.confirm_delete_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await deleteUserApiKey(keyId);
      await loadSettings();
      showApiKeyFeedback(t("messages.settings_api_key_deleted"), "success");
    } catch (error) {
      showApiKeyFeedback(error.message || t("messages.settings_action_error"), "error");
    }
    return;
  }

}

const EMAIL_TEMPLATE_KEYS_ORDER = [
  "invitation",
  "password_reset",
  "email_verification",
  "magic_login",
  "smtp_test",
  "announcement",
  "notification_test",
  "notification_event",
];

function getEmailTemplateBtns() {
  return [
    document.getElementById("email-template-save-btn"),
    document.getElementById("email-template-preview-btn"),
    document.getElementById("email-template-reset-btn"),
  ].filter(Boolean);
}

function setEmailTemplateBtnsDisabled(btns, disabled) {
  btns.forEach((btn) => { btn.disabled = disabled; });
}

function updateEmailTemplateCustomBadge(isCustom) {
  const badge = document.getElementById("email-template-custom-badge");
  if (!badge) return;
  badge.textContent = isCustom ? t("admin.email_templates.custom") : t("admin.email_templates.default");
  badge.className = isCustom ? "badge badge-premium" : "badge";
}

function showEmailTemplatePreview(result) {
  const block = document.getElementById("email-template-preview-block");
  const subjectEl = document.getElementById("email-template-preview-subject");
  const bodyEl = document.getElementById("email-template-preview-body");
  const sampleEl = document.getElementById("email-template-preview-sample");
  if (!block || !subjectEl || !bodyEl) return;

  subjectEl.textContent = result.subject || "";
  bodyEl.textContent = result.body || "";
  if (sampleEl && result.sample_values) {
    sampleEl.textContent = JSON.stringify(result.sample_values, null, 2);
  }
  block.hidden = false;
}

function hideEmailTemplatePreview() {
  const block = document.getElementById("email-template-preview-block");
  if (block) block.hidden = true;
}

function insertAtCursor(textarea, text) {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  textarea.value = textarea.value.slice(0, start) + text + textarea.value.slice(end);
  textarea.selectionStart = textarea.selectionEnd = start + text.length;
  textarea.focus();
}

async function loadEmailTemplateIntoPanel(key, lang) {
  const feedbackEl = document.getElementById("admin-email-templates-feedback");
  if (feedbackEl) feedbackEl.hidden = true;
  hideEmailTemplatePreview();

  const btns = getEmailTemplateBtns();
  setEmailTemplateBtnsDisabled(btns, true);

  try {
    const tmpl = await getEmailTemplate(key, lang);

    const subjectInput = document.getElementById("email-template-subject");
    const bodyTextarea = document.getElementById("email-template-body");
    if (subjectInput) subjectInput.value = tmpl.subject_template || "";
    if (bodyTextarea) bodyTextarea.value = tmpl.body_template || "";

    updateEmailTemplateCustomBadge(tmpl.is_custom);

    const variablesContainer = document.getElementById("email-template-variables");
    const variablesBlock = document.getElementById("email-template-variables-block");
    const variables = Array.isArray(tmpl.available_variables) ? tmpl.available_variables : [];

    if (variables.length > 0 && variablesContainer && variablesBlock) {
      variablesContainer.innerHTML = variables
        .map((v) => `<button type="button" class="email-template-variable-badge" data-action="insert-template-variable" data-variable="${v}">{${v}}</button>`)
        .join("");
      variablesBlock.hidden = false;
    } else if (variablesBlock) {
      variablesBlock.hidden = true;
    }

    const keySelect = document.getElementById("email-template-key-select");
    const langSelect = document.getElementById("email-template-lang-select");
    if (keySelect) keySelect.value = key;
    if (langSelect) langSelect.value = lang;
  } catch (error) {
    showAdminFeedback("email-templates", error.message || t("admin.email_templates.load_error"), "error");
  } finally {
    setEmailTemplateBtnsDisabled(btns, false);
  }
}

async function initEmailTemplatesPanel() {
  const keySelect = document.getElementById("email-template-key-select");
  if (!keySelect) return;

  if (!keySelect.options.length) {
    keySelect.innerHTML = EMAIL_TEMPLATE_KEYS_ORDER
      .map((key) => `<option value="${key}">${t(`admin.email_templates.key_${key}`)}</option>`)
      .join("");
  }

  const langSelect = document.getElementById("email-template-lang-select");
  const currentKey = keySelect.value || EMAIL_TEMPLATE_KEYS_ORDER[0];
  const currentLang = langSelect?.value || (state.language === "fr" ? "fr" : "en");
  if (langSelect) langSelect.value = currentLang;

  await loadEmailTemplateIntoPanel(currentKey, currentLang);
}

async function handleAdminSubmit(form) {

  if (form.id === "admin-general-form") {
    const payload = {
      app_name: form.app_name?.value?.trim() || "",
      app_tagline: form.app_tagline?.value?.trim() || "",
      public_base_url: form.public_base_url?.value?.trim() || "",
    };
    try {
      const saved = await saveAdminGeneralSettings(payload);
      state.generalSettings = saved;
      state.activeAdminTab = "general";
      await loadAdmin();
      switchAdminTab("general");
      showAdminFeedback("general", t("messages.admin_general_saved"), "success");
    } catch (error) {
      showAdminFeedback("general", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (form.id === "admin-smtp-form") {
    const payload = buildSmtpSettingsPayload(form);
    try {
      await saveAdminSmtpSettings(payload);
      state.activeAdminTab = "smtp";
      await loadAdmin();
      switchAdminTab("smtp");
      showAdminFeedback("smtp", t("messages.admin_smtp_saved"), "success");
    } catch (error) {
      showAdminFeedback("smtp", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }
  if (form.id === "admin-security-form") {
    const payload = buildSecuritySettingsPayload(form);
    try {
      await saveAdminSecuritySettings(payload);
      state.activeAdminTab = "security";
      await loadAdmin();
      switchAdminTab("security");
      showAdminFeedback("security", t("messages.admin_security_saved"), "success");
    } catch (error) {
      showAdminFeedback("security", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (form.id === "admin-cleanup-form") {
    const payload = buildCleanupSettingsPayload(form);
    try {
      await saveAdminCleanupSettings(payload);
      state.activeAdminTab = "cleanup";
      await loadAdmin();
      switchAdminTab("cleanup");
      showAdminFeedback("cleanup", t("messages.admin_cleanup_saved"), "success");
    } catch (error) {
      showAdminFeedback("cleanup", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }
  if (form.id === "user-form") {
    const creationMode = form.creation_mode?.value || "password";

    try {
      const result = await createUser({
        email: form.email.value,
        display_name: form.display_name.value,
        creation_mode: creationMode,
        password: creationMode === "password" ? form.password.value : undefined,
        force_password_change: creationMode === "password"
          ? Boolean(form.force_password_change?.checked)
          : false,
        is_super_admin: Boolean(form.is_super_admin.checked),
        email_verified: Boolean(form.email_verified?.checked),
        valid_from: getOptionalDatetimeValue(form, "valid_from"),
        account_expires_at: getOptionalDatetimeValue(form, "account_expires_at"),
        preferred_language: form.preferred_language.value,
        can_use_local_space: Boolean(form.can_use_local_space?.checked),
      });

      form.reset();
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_created"), "success");

      if (result.invitation?.invitation_url) {
        await showLinkModal({
          title: t("admin.users.modal_invite_title"),
          message: t("admin.users.modal_invite_message_create"),
          link: result.invitation.invitation_url,
          expiresAt: result.invitation.expires_at,
          copyLabel: t("common.copy"),
          closeLabel: t("common.close"),
        });
      }
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }

    return;
  }
  if (form.classList.contains("user-edit-form")) {
    const userId = form.dataset.userId;

    try {
      await updateUser(userId, {
        email: form.email.value,
        display_name: form.display_name.value,
        is_super_admin: Boolean(form.is_super_admin.checked),
        is_active: Boolean(form.is_active.checked),
        email_verified: Boolean(form.email_verified.checked),
        valid_from: getOptionalDatetimeValue(form, "valid_from"),
        account_expires_at: getOptionalDatetimeValue(form, "account_expires_at"),
        preferred_language: form.preferred_language.value,
        can_use_local_space: Boolean(form.can_use_local_space?.checked),
      });

      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_updated"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }

    return;
  }

  if (form.classList.contains("user-password-form")) {
    const userId = form.dataset.userId;

    try {
      await resetUserPassword(userId, form.password.value);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_password_reset"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }

    return;
  }
  if (form.id === "admin-timeouts-form") {
    const payload = buildRestartCooldownsPayload(form);
    try {
      const saved = await saveAdminRestartCooldowns(payload);
      state.restartCooldowns = saved;
      state.timeoutSettings = saved;
      state.activeAdminTab = "timeouts";
      await loadAdmin();
      switchAdminTab("timeouts");
      showAdminFeedback("timeouts", t("messages.admin_timeouts_saved"), "success");
    } catch (error) {
      showAdminFeedback("timeouts", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (form.id === "admin-runtime-form") {
    const payload = buildRuntimeSettingsPayload(form);
    try {
      const saved = await saveAdminRuntimeSettings(payload);
      state.runtimeSettings = saved;
      state.activeAdminTab = "runtime";
      await loadAdmin();
      switchAdminTab("runtime");
      showAdminFeedback("runtime", t("messages.admin_runtime_saved"), "success");
    } catch (error) {
      showAdminFeedback("runtime", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (form.id === "announcement-create-form") {
    const payload = buildAnnouncementPayload(form);
    try {
      await createAdminAnnouncement(payload);
      state.activeAdminTab = "announcements";
      await loadAdmin();
      switchAdminTab("announcements");
      const details = document.querySelector('[data-admin-panel="announcements"] details');
      if (details) details.open = false;
      showAdminFeedback("announcements", t("admin.announcements.created"), "success");
    } catch (error) {
      const msg = error.status === 503
        ? t("admin.announcements.email_send_failed_smtp")
        : error.message || t("messages.admin_action_error");
      showAdminFeedback("announcements", msg, "error");
    }
    return;
  }

  if (form.classList.contains("announcement-edit-form-inline")) {
    const annId = form.dataset.announcementId;
    if (!annId) return;
    const payload = buildAnnouncementPayload(form);
    try {
      await updateAdminAnnouncement(annId, payload);
      state.activeAdminTab = "announcements";
      await loadAdmin();
      switchAdminTab("announcements");
      showAdminFeedback("announcements", t("admin.announcements.updated"), "success");
    } catch (error) {
      showAdminFeedback("announcements", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

}

function buildAnnouncementPayload(form) {
  const startsAtVal = form.starts_at?.value;
  const endsAtVal = form.ends_at?.value;
  return {
    title: String(form.title?.value || "").trim(),
    body: String(form.body?.value || "").trim(),
    type: form.type?.value || "news",
    severity: form.severity?.value || "info",
    is_active: Boolean(form.is_active?.checked),
    show_as_banner: Boolean(form.show_as_banner?.checked),
    require_acknowledgement: Boolean(form.require_acknowledgement?.checked),
    track_open: Boolean(form.track_open?.checked),
    send_email: Boolean(form.send_email?.checked),
    starts_at: startsAtVal ? new Date(startsAtVal).toISOString() : null,
    ends_at: endsAtVal ? new Date(endsAtVal).toISOString() : null,
  };
}

function formatCleanupResult(result) {
  const errors = Array.isArray(result?.temp_files_errors)
    ? result.temp_files_errors
    : [];

  const parts = [
    `${t("admin.cleanup.result_tokens")}: ${Number(result?.tokens_deleted || 0)}`,
    `${t("admin.cleanup.result_completed")}: ${Number(result?.completed_jobs_deleted || 0)}`,
    `${t("admin.cleanup.result_failed")}: ${Number(result?.failed_jobs_deleted || 0)}`,
    `${t("admin.cleanup.result_cancelled")}: ${Number(result?.cancelled_jobs_deleted || 0)}`,
    `${t("admin.cleanup.result_temp_files")}: ${Number(result?.temp_files_deleted || 0)}`,
  ];

  if (errors.length > 0) {
    parts.push(`${t("admin.cleanup.result_file_errors")}: ${errors.length}`);
  }

  return parts.join(" | ");
}

async function handleAdminClick(button) {
  const action = button.dataset.action;
  const id = button.dataset.id;

  if (action === "test-admin-smtp") {
    try {
      const result = await testAdminSmtpSettings();
      showAdminFeedback("smtp", result.message || t("messages.admin_smtp_test_sent"), "success");
    } catch (error) {
      showAdminFeedback("smtp", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "run-admin-cleanup") {
    const confirmed = await showConfirmModal({
      title: t("admin.cleanup.confirm_title"),
      message: t("admin.cleanup.confirm_message"),
      confirmLabel: t("admin.cleanup.confirm_run"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      const result = await runAdminCleanup();
      state.activeAdminTab = "cleanup";
      await loadAdmin();
      switchAdminTab("cleanup");
      showAdminFeedback(
        "cleanup",
        `${t("messages.admin_cleanup_run")} ${formatCleanupResult(result)}`,
        "success"
      );
    } catch (error) {
      showAdminFeedback("cleanup", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "refresh-admin-maintenance") {
    const token = localStorage.getItem("link2nas_token");

    if (!token && !state.currentUser?.single_user_mode) {
      showAppMessage(t("messages.session_expired"), "error");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
      return;
    }

    try {
      const result = await getAdminMaintenanceStatus();
      state.maintenanceStatus = result;
      state.activeAdminTab = "maintenance";
      await loadAdmin();
      switchAdminTab("maintenance");
      showAdminFeedback(
        "maintenance",
        t("messages.admin_maintenance_refreshed"),
        result.ok ? "success" : "info"
      );
    } catch (error) {
      showAdminFeedback("maintenance", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }
  if (action === "toggle-user-edit") {
    const card = button.closest("[data-user-id]");
    const editContent = card?.querySelector(".admin-user-edit-content");
    if (editContent) {
      editContent.hidden = !editContent.hidden;
      button.classList.toggle("is-active", !editContent.hidden);
    }
    return;
  }

  if (action === "disable-user") {
    try {
      await disableUser(id);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_disabled"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "enable-user") {
    try {
      await enableUser(id);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_enabled"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "verify-user-email") {
    try {
      await verifyUserEmail(id);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_email_verified"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "create-user-invitation") {
    try {
      const result = await createUserInvitation(id);
      await showLinkModal({
        title: t("admin.users.modal_invite_title"),
        message: t("admin.users.modal_invite_message_resend"),
        link: result.invitation_url,
        expiresAt: result.expires_at,
        copyLabel: t("common.copy"),
        closeLabel: t("common.close"),
      });
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "send-user-invitation-email") {
    const smtpOk = !!(state.smtpSettings?.enabled && state.smtpSettings?.host && state.smtpSettings?.port && state.smtpSettings?.from_email);
    if (!smtpOk) {
      showAdminFeedback("users", t("email.smtp_configure_hint"), "error");
      return;
    }

    const confirmed = await showConfirmModal({
      title: t("admin.users.confirm_send_invite_title"),
      message: t("admin.users.confirm_send_invite_message"),
      confirmLabel: t("admin.users.confirm_send"),
      cancelLabel: t("common.cancel"),
    });

    if (!confirmed) return;

    try {
      await sendUserInvitationEmail(id);
      showAdminFeedback("users", t("messages.admin_user_invitation_sent"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "create-user-password-reset-link") {
    try {
      const result = await createUserPasswordResetLink(id);
      await showLinkModal({
        title: t("admin.users.modal_reset_title"),
        message: t("admin.users.modal_reset_message"),
        link: result.reset_url,
        expiresAt: result.expires_at,
        copyLabel: t("common.copy"),
        closeLabel: t("common.close"),
      });
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "send-user-password-reset-email") {
    const smtpOk = !!(state.smtpSettings?.enabled && state.smtpSettings?.host && state.smtpSettings?.port && state.smtpSettings?.from_email);
    if (!smtpOk) {
      showAdminFeedback("users", t("email.smtp_configure_hint"), "error");
      return;
    }

    const confirmed = await showConfirmModal({
      title: t("admin.users.confirm_send_reset_title"),
      message: t("admin.users.confirm_send_reset_message"),
      confirmLabel: t("admin.users.confirm_send"),
      cancelLabel: t("common.cancel"),
    });

    if (!confirmed) return;

    try {
      await sendUserPasswordResetEmail(id);
      showAdminFeedback("users", t("messages.admin_user_reset_sent"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "delete-user") {
    const confirmed = await showConfirmModal({
      title: t("admin.users.confirm_delete_title"),
      message: t("admin.users.confirm_delete_message"),
      confirmLabel: t("common.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });

    if (!confirmed) return;

    try {
      await deleteUser(id);
      state.activeAdminTab = "users";
      await loadAdmin();
      switchAdminTab("users");
      showAdminFeedback("users", t("messages.admin_user_deleted"), "success");
    } catch (error) {
      showAdminFeedback("users", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }
  if (action === "run-notification-dispatcher-now") {
    const limit = Number(
      document.querySelector("[name='notification_dispatcher_limit']")?.value || 25
    );
    try {
      const result = await runAdminNotificationDispatcherOnce(limit);
      state.activeAdminTab = "runtime";
      await loadAdmin();
      switchAdminTab("runtime");
      showAdminFeedback(
        "runtime",
        `${t("messages.admin_dispatcher_run")} processed=${result.processed || 0}, sent=${result.sent || 0}, retrying=${result.retrying || 0}, failed=${result.failed || 0}`,
        result.errors?.length ? "info" : "success"
      );
    } catch (error) {
      showAdminFeedback("runtime", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "refresh-notification-dispatcher-status") {
    try {
      const result = await getAdminNotificationDispatcherStatus();
      state.activeAdminTab = "runtime";
      await loadAdmin();
      switchAdminTab("runtime");
      showAdminFeedback(
        "runtime",
        result.last_error ? result.last_error : t("messages.admin_dispatcher_refreshed"),
        result.last_error ? "info" : "success"
      );
    } catch (error) {
      showAdminFeedback("runtime", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "edit-announcement") {
    const annId = id;
    if (!annId) return;
    const ann = state.adminAnnouncements.find((a) => a.id === annId);
    if (!ann) return;
    const inlineEl = document.querySelector(`.announcement-edit-inline[data-for-announcement="${annId}"]`);
    if (!inlineEl) return;
    if (!inlineEl.hidden) {
      inlineEl.hidden = true;
      return;
    }
    const emailAvailableForForm = Boolean(state.currentUser?.email_sending_available);
    inlineEl.innerHTML = renderAnnouncementForm(ann, emailAvailableForForm);
    const inlineForm = inlineEl.querySelector("form");
    if (inlineForm) inlineForm.classList.add("announcement-edit-form-inline");
    inlineEl.hidden = false;
    return;
  }

  if (action === "cancel-announcement-edit") {
    const annId = id;
    const inlineEl = document.querySelector(`.announcement-edit-inline[data-for-announcement="${annId}"]`);
    if (inlineEl) inlineEl.hidden = true;
    return;
  }

  if (action === "delete-announcement") {
    const annId = id;
    if (!annId) return;
    const confirmed = await showConfirmModal({
      title: t("admin.announcements.confirm_delete_title"),
      message: t("admin.announcements.confirm_delete"),
      confirmLabel: t("admin.announcements.delete"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });
    if (!confirmed) return;
    try {
      await deleteAdminAnnouncement(annId);
      state.activeAdminTab = "announcements";
      await loadAdmin();
      switchAdminTab("announcements");
      showAdminFeedback("announcements", t("admin.announcements.deleted"), "success");
    } catch (error) {
      showAdminFeedback("announcements", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "activate-announcement" || action === "deactivate-announcement") {
    const annId = id;
    if (!annId) return;
    const isActivating = action === "activate-announcement";
    try {
      await updateAdminAnnouncement(annId, { is_active: isActivating });
      state.activeAdminTab = "announcements";
      await loadAdmin();
      switchAdminTab("announcements");
      showAdminFeedback("announcements", t("admin.announcements.updated"), "success");
    } catch (error) {
      showAdminFeedback("announcements", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "view-announcement-tracking") {
    const annId = id;
    if (!annId) return;
    const inlineEl = document.querySelector(`.announcement-tracking-inline[data-for-tracking="${annId}"]`);
    if (!inlineEl) return;
    if (!inlineEl.hidden) {
      inlineEl.hidden = true;
      return;
    }
    try {
      const tracking = await getAdminAnnouncementTracking(annId);
      state.announcementTrackingById[annId] = tracking;
      inlineEl.innerHTML = renderAnnouncementTrackingPanel(tracking);
      inlineEl.hidden = false;
    } catch (error) {
      showAdminFeedback("announcements", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "insert-template-variable") {
    const variable = button.dataset.variable;
    if (!variable) return;
    const textarea = document.getElementById("email-template-body");
    if (!textarea) return;
    insertAtCursor(textarea, `{${variable}}`);
    return;
  }

  if (action === "email-template-save") {
    const key = document.getElementById("email-template-key-select")?.value;
    const lang = document.getElementById("email-template-lang-select")?.value;
    const subject = document.getElementById("email-template-subject")?.value || "";
    const body = document.getElementById("email-template-body")?.value || "";
    if (!key || !lang) return;

    const btns = getEmailTemplateBtns();
    setEmailTemplateBtnsDisabled(btns, true);
    try {
      const saved = await saveEmailTemplate(key, lang, { subject_template: subject, body_template: body });
      updateEmailTemplateCustomBadge(saved.is_custom);
      showAdminFeedback("email-templates", t("admin.email_templates.saved"), "success");
    } catch (error) {
      showAdminFeedback("email-templates", error.message || t("admin.email_templates.save_error"), "error");
    } finally {
      setEmailTemplateBtnsDisabled(btns, false);
    }
    return;
  }

  if (action === "email-template-preview") {
    const key = document.getElementById("email-template-key-select")?.value;
    const lang = document.getElementById("email-template-lang-select")?.value;
    const subject = document.getElementById("email-template-subject")?.value || "";
    const body = document.getElementById("email-template-body")?.value || "";
    if (!key || !lang) return;

    const btns = getEmailTemplateBtns();
    setEmailTemplateBtnsDisabled(btns, true);
    hideEmailTemplatePreview();
    try {
      const result = await previewEmailTemplate(key, lang, { subject_template: subject, body_template: body });
      showEmailTemplatePreview(result);
    } catch (error) {
      showAdminFeedback("email-templates", error.message || t("admin.email_templates.preview_error"), "error");
    } finally {
      setEmailTemplateBtnsDisabled(btns, false);
    }
    return;
  }

  if (action === "email-template-reset") {
    const key = document.getElementById("email-template-key-select")?.value;
    const lang = document.getElementById("email-template-lang-select")?.value;
    if (!key || !lang) return;

    const confirmed = await showConfirmModal({
      title: t("admin.email_templates.reset"),
      message: t("admin.email_templates.reset_confirm"),
      confirmLabel: t("admin.email_templates.reset"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });
    if (!confirmed) return;

    const btns = getEmailTemplateBtns();
    setEmailTemplateBtnsDisabled(btns, true);
    try {
      await resetEmailTemplate(key, lang);
      await loadEmailTemplateIntoPanel(key, lang);
      showAdminFeedback("email-templates", t("admin.email_templates.reset_done"), "success");
    } catch (error) {
      showAdminFeedback("email-templates", error.message || t("admin.email_templates.reset_error"), "error");
    } finally {
      setEmailTemplateBtnsDisabled(btns, false);
    }
    return;
  }

  if (action === "refresh-anti-abuse") {
    try {
      await loadAntiAbuseSection();
      showAdminFeedback("anti-abuse", t("messages.admin_maintenance_refreshed"), "success");
    } catch (error) {
      showAdminFeedback("anti-abuse", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "reset-anti-abuse-all") {
    const confirmed = await showConfirmModal({
      title: t("admin.security.anti_abuse.reset_all_confirm_title"),
      message: t("admin.security.anti_abuse.reset_all_confirm_message"),
      confirmLabel: t("admin.security.anti_abuse.reset_all"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });
    if (!confirmed) return;

    try {
      await resetAdminAntiAbuseAll();
      await loadAntiAbuseSection();
      showAdminFeedback("anti-abuse", t("messages.admin_anti_abuse_reset_all"), "success");
    } catch (error) {
      showAdminFeedback("anti-abuse", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

  if (action === "reset-anti-abuse-kind") {
    const kind = button.dataset.kind;
    if (!kind) return;

    const confirmed = await showConfirmModal({
      title: t("admin.security.anti_abuse.reset_kind_confirm_title"),
      message: t("admin.security.anti_abuse.reset_kind_confirm_message"),
      confirmLabel: t("admin.security.anti_abuse.reset_kind"),
      cancelLabel: t("common.cancel"),
      danger: true,
    });
    if (!confirmed) return;

    try {
      await resetAdminAntiAbuseKind(kind);
      await loadAntiAbuseSection();
      showAdminFeedback("anti-abuse", t("messages.admin_anti_abuse_reset_kind"), "success");
    } catch (error) {
      showAdminFeedback("anti-abuse", error.message || t("messages.admin_action_error"), "error");
    }
    return;
  }

}

const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };

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

async function loadAndRenderBanner() {
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

function bindAuthEvents() {
  document.getElementById("setup-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;

    try {
      await createFirstAdmin({
        email: form.email.value,
        display_name: form.display_name.value,
        password: form.password.value,
      });

      showAppMessage(t("messages.super_admin_created"), "success");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });

  document.getElementById("login-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;

    try {
      const result = await login({
        email: form.email.value,
        password: form.password.value,
      });

      localStorage.setItem("link2nas_token", result.token);
      state.currentUser = result.user;
      applyCurrentUserTheme(result.user);
      updateAuthVisibility();

      if (result.user?.force_password_change) {
        renderForcedPasswordChangeForm();
        bindAuthEvents();
        showAppMessage(t("messages.must_change_password"), "info");
        return;
      }

      hideAdminIfNeeded();

      await enterMainApplication({ useHomePage: true });
    } catch (error) {
      showAppMessage(error.message || t("auth.error.invalid_credentials"), "error");
    }
  });

  document.getElementById("show-magic-login-btn")?.addEventListener("click", () => {
    renderMagicLoginRequestForm();
    bindAuthEvents();
  });

  document.getElementById("magic-login-request-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const email = String(form.email?.value || "").trim();

    if (!email) {
      showAppMessage(t("auth.error.email_required"), "error");
      return;
    }

    try {
      const result = await requestMagicLogin(email);
      showAppMessage(
        result.message || t("auth.magic_login_sent"),
        "success"
      );
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("auth.error.magic_login_send_failed"), "error");
    }
  });

  document.getElementById("accept-invitation-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const password = validatePasswordConfirmation(form);
    if (!password) return;

    try {
      await acceptInvitation(form.token.value, password);

      clearPublicAccountUrl();
      showAppMessage(t("messages.account_activated"), "success");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });

  document.getElementById("password-reset-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const password = validatePasswordConfirmation(form);
    if (!password) return;

    try {
      await confirmPasswordReset(form.token.value, password);

      clearPublicAccountUrl();
      showAppMessage(t("messages.password_reset_done"), "success");
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("auth.error.password_reset_failed"), "error");
    }
  });

  document.getElementById("back-to-login-btn")?.addEventListener("click", () => {
    clearPublicAccountUrl();
    renderLoginForm(state.appInfo?.email_sending_available ?? true);
    bindAuthEvents();
  });

  document.getElementById("forced-password-change-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const payload = validateForcedPasswordChangeForm(form);
    if (!payload) return;

    try {
      await changeMyPassword(payload);

      const me = await getMe();
      state.currentUser = me;
      applyCurrentUserTheme(me);
      updateAuthVisibility();

      if (me.force_password_change) {
        showAppMessage(t("auth.error.password_change_not_finalized"), "error");
        return;
      }

      hideAdminIfNeeded();

      showAppMessage(t("messages.settings_password_changed"), "success");
      await enterMainApplication({ useHomePage: true });

    } catch (error) {
      showAppMessage(error.message || t("messages.settings_action_error"), "error");
    }
  });

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

async function handlePublicAccountRoute() {
  if (
    !isInviteRoute() &&
    !isPasswordResetRoute() &&
    !isMagicLoginRoute() &&
    !isEmailVerificationRoute()
  ) {
    return false;
  }

  localStorage.removeItem("link2nas_token");
  state.currentUser = null;
  updateAuthVisibility();

  const token = getPublicTokenFromUrl();

  if (!token) {
    renderInvalidToken(t("auth.error.token_missing"));
    bindAuthEvents();
    return true;
  }

  try {
    const tokenStatus = await getPublicTokenStatus(token);

    if (isInviteRoute()) {
      if (tokenStatus.token_type !== "invitation") {
        renderInvalidToken(t("auth.error.not_invitation_link"));
        bindAuthEvents();
        return true;
      }

      renderAcceptInvitationForm(token, tokenStatus);
      bindAuthEvents();
      return true;
    }

    if (isPasswordResetRoute()) {
      if (tokenStatus.token_type !== "password_reset") {
        renderInvalidToken(t("auth.error.not_reset_link"));
        bindAuthEvents();
        return true;
      }

      renderPasswordResetForm(token, tokenStatus);
      bindAuthEvents();
      return true;
    }

    if (isMagicLoginRoute()) {
      renderMagicLoginProcessing();

      try {
        const result = await confirmMagicLogin(token);

        localStorage.setItem("link2nas_token", result.token);
        state.currentUser = result.user;
        applyCurrentUserTheme(result.user);
        updateAuthVisibility();

        clearPublicAccountUrl();

        if (result.user?.force_password_change) {
          renderForcedPasswordChangeForm();
          bindAuthEvents();
          showAppMessage(t("messages.must_change_password"), "info");
          return true;
        }

        hideAdminIfNeeded();
        await enterMainApplication({ useHomePage: true });

        return true;
      } catch (error) {
        renderInvalidToken(error.message || t("auth.error.magic_link_invalid"));
        bindAuthEvents();
        return true;
      }
    }

    if (isEmailVerificationRoute()) {
      renderEmailVerificationProcessing();

      try {
        await confirmEmailVerification(token);

        clearPublicAccountUrl();
        showAppMessage(t("messages.email_validated"), "success");

        const existingToken = localStorage.getItem("link2nas_token");
        if (existingToken) {
          try {
            state.currentUser = await getMe();
            applyCurrentUserTheme(state.currentUser);
            updateAuthVisibility();
            await enterMainApplication();
            return true;
          } catch {
            localStorage.removeItem("link2nas_token");
          }
        }

        renderLoginForm(state.appInfo?.email_sending_available ?? true);
        bindAuthEvents();
        return true;
      } catch (error) {
        renderInvalidToken(error.message || t("auth.error.email_verification_invalid"));
        bindAuthEvents();
        return true;
      }
    }

  } catch (error) {
    renderInvalidToken(error.message || t("auth.invalid_token_message"));
    bindAuthEvents();
    return true;
  }

  return false;
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

bootstrap().catch((error) => {
  console.error(error);
});