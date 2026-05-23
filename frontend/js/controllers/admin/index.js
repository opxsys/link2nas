import { getToken } from "../../core/session.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
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
  getAdminAntiAbuse,
  resetAdminAntiAbuseAll,
  resetAdminAntiAbuseKind,
} from "../../api.js";
import {
  renderUsersPanel,
  renderAnnouncementForm,
  renderAnnouncementTrackingPanel,
  renderAntiAbuseSection,
} from "../../render/admin.js";
import { renderLoginForm } from "../../render/auth.js";
import { showAppMessage } from "../../utils.js";
import { showConfirmModal, showLinkModal } from "../../ui/modals.js";
import { renderStaticTexts } from "../navigation-controller.js";
import { bindAuthEvents } from "../auth-controller.js";
import { showAdminFeedback } from "./feedback.js";
import { getFilteredAdminUsers, bindAdminUsersFilters } from "./users-filters.js";
import { getOptionalDatetimeValue, buildSmtpSettingsPayload, buildSecuritySettingsPayload, buildCleanupSettingsPayload, buildRestartCooldownsPayload, buildRuntimeSettingsPayload, buildAnnouncementPayload, formatCleanupResult } from "./payloads.js";
import { loadEmailTemplateIntoPanel, initEmailTemplatesPanel } from "./email-templates.js";
import { handleEmailTemplateAction } from "./email-template-actions.js";

export { showAdminFeedback, getFilteredAdminUsers, bindAdminUsersFilters, loadEmailTemplateIntoPanel, initEmailTemplatesPanel };

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

export async function handleAdminClick(button) {
  const action = button.dataset.action;
  const id = button.dataset.id;

  if (await handleEmailTemplateAction(action, button)) return;

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
