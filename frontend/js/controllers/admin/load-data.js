import { state } from "../../state.js";
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

export async function loadAdminData() {
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

  return {
    isSingleUserMode,
    users,
    smtpSettings,
    securitySettings,
    cleanupSettings,
    maintenanceStatus,
    timeoutSettings,
    runtimeSettings,
    generalSettings,
    adminAnnouncements: state.adminAnnouncements,
    emailAvailable,
  };
}
