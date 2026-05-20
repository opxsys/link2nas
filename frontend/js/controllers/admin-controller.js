import { getToken } from "../core/session.js";
import { state } from "../state.js";
import { t } from "../i18n/index.js";
import {
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
  getAdminSmtpSettings,
  getAdminSecuritySettings,
  saveAdminSecuritySettings,
  getAdminCleanupSettings,
  saveAdminCleanupSettings,
  runAdminCleanup,
  getAdminMaintenanceStatus,
  saveAdminSmtpSettings,
  testAdminSmtpSettings,
  getAdminRestartCooldowns,
  saveAdminRestartCooldowns,
  getAdminRuntimeSettings,
  saveAdminRuntimeSettings,
  getAdminNotificationDispatcherStatus,
  runAdminNotificationDispatcherOnce,
  getAdminGeneralSettings,
  saveAdminGeneralSettings,
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
} from "../api.js";
import {
  renderUsersPanel,
  renderUserCardList,
  renderAnnouncementForm,
  renderAnnouncementTrackingPanel,
  renderAntiAbuseSection,
} from "../render/admin.js";
import { renderLoginForm } from "../render/auth.js";
import { showAppMessage } from "../utils.js";
import { showConfirmModal, showLinkModal } from "../ui/modals.js";
import { renderStaticTexts } from "./navigation-controller.js";
import { bindAuthEvents } from "./auth-controller.js";

export function showAdminFeedback(section, message, type = "info") {
  const el = document.getElementById(`admin-${section}-feedback`);
  if (!el) { showAppMessage(message, type); return; }
  el.textContent = message;
  el.className = `admin-feedback admin-feedback-${type}`;
  el.hidden = false;
}

export function getFilteredAdminUsers(users, query, filter) {
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

export function bindAdminUsersFilters() {
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

export async function loadAntiAbuseSection() {
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

export async function loadAdmin() {
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

export function switchAdminTab(tabName) {
  const fallbackTab = state.currentUser?.single_user_mode ? "maintenance" : "users";
  const selectedTab = String(tabName || fallbackTab).trim();

  document.querySelectorAll("[data-admin-tab]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.adminTab === selectedTab);
  });

  document.querySelectorAll("[data-admin-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.adminPanel !== selectedTab;
  });
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

export function updateUserCreationModeFields() {
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

export async function loadEmailTemplateIntoPanel(key, lang) {
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

export async function initEmailTemplatesPanel() {
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

export async function handleAdminSubmit(form) {

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

export async function handleAdminClick(button) {
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
    const token = getToken();

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
