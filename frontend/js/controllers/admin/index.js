import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import {
  listUsers,
  getAdminSmtpSettings,
  getAdminSecuritySettings,
  getAdminCleanupSettings,
  getAdminMaintenanceStatus,
  getAdminRestartCooldowns,
  getAdminRuntimeSettings,
  getAdminGeneralSettings,
  listAdminAnnouncements,
} from "../../api.js";
import { renderUsersPanel } from "../../render/admin.js";
import { renderStaticTexts } from "../navigation-controller.js";
import { showAdminFeedback } from "./feedback.js";
import { getFilteredAdminUsers, bindAdminUsersFilters } from "./users-filters.js";
import { handleSettingsSubmit } from "./settings-submit.js";
import { handleUserSubmit } from "./user-submit.js";
import { handleAnnouncementSubmit } from "./announcement-submit.js";
import { loadEmailTemplateIntoPanel, initEmailTemplatesPanel } from "./email-templates.js";
import { handleEmailTemplateAction } from "./email-template-actions.js";
import { loadAntiAbuseSection } from "./anti-abuse.js";
import { handleAntiAbuseAction } from "./anti-abuse-actions.js";
import { handleUserAction } from "./user-actions.js";
import { handleSystemAction } from "./system-actions.js";
import { handleAnnouncementAction } from "./announcement-actions.js";

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
  if (await handleSystemAction(action, button)) return;
  if (await handleAnnouncementAction(action, button)) return;

}
