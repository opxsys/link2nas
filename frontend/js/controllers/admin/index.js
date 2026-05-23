import { getToken } from "../../core/session.js";
import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import {
  listUsers,
  getAdminSmtpSettings,
  getAdminSecuritySettings,
  getAdminCleanupSettings,
  runAdminCleanup,
  getAdminMaintenanceStatus,
  testAdminSmtpSettings,
  getAdminRestartCooldowns,
  getAdminRuntimeSettings,
  getAdminNotificationDispatcherStatus,
  runAdminNotificationDispatcherOnce,
  getAdminGeneralSettings,
  listAdminAnnouncements,
  updateAdminAnnouncement,
  deleteAdminAnnouncement,
  getAdminAnnouncementTracking,
} from "../../api.js";
import {
  renderUsersPanel,
  renderAnnouncementForm,
  renderAnnouncementTrackingPanel,
} from "../../render/admin.js";
import { renderLoginForm } from "../../render/auth.js";
import { showAppMessage } from "../../utils.js";
import { showConfirmModal } from "../../ui/modals.js";
import { renderStaticTexts } from "../navigation-controller.js";
import { bindAuthEvents } from "../auth-controller.js";
import { showAdminFeedback } from "./feedback.js";
import { getFilteredAdminUsers, bindAdminUsersFilters } from "./users-filters.js";
import { formatCleanupResult } from "./payloads.js";
import { handleSettingsSubmit } from "./settings-submit.js";
import { handleUserSubmit } from "./user-submit.js";
import { handleAnnouncementSubmit } from "./announcement-submit.js";
import { loadEmailTemplateIntoPanel, initEmailTemplatesPanel } from "./email-templates.js";
import { handleEmailTemplateAction } from "./email-template-actions.js";
import { loadAntiAbuseSection } from "./anti-abuse.js";
import { handleAntiAbuseAction } from "./anti-abuse-actions.js";
import { handleUserAction } from "./user-actions.js";

export { showAdminFeedback, getFilteredAdminUsers, bindAdminUsersFilters, loadEmailTemplateIntoPanel, initEmailTemplatesPanel, loadAntiAbuseSection };

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

  if (await handleSettingsSubmit(form)) return;
  if (await handleUserSubmit(form)) return;
  if (await handleAnnouncementSubmit(form)) return;

}

export async function handleAdminClick(button) {
  const action = button.dataset.action;
  const id = button.dataset.id;

  if (await handleEmailTemplateAction(action, button)) return;
  if (await handleAntiAbuseAction(action, button)) return;
  if (await handleUserAction(action, button)) return;

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

}
