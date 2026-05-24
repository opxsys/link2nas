import { renderGeneralSettingsPanel } from "./general.js";
import { renderSmtpSettingsPanel } from "./smtp.js";
import { renderSecuritySettingsPanel } from "./security.js";
import { renderCleanupSettingsPanel } from "./cleanup.js";
import { renderTimeoutsSettingsPanel } from "./timeouts.js";
import { renderMaintenanceStatusPanel } from "./maintenance.js";
import { renderRuntimeSettingsPanel } from "./runtime.js";
import { renderEmailTemplatesPanel } from "./email-templates.js";
import { renderAnnouncementsAdminPanel } from "./announcements.js";

export function renderAdminSectionPlaceholders(
  smtpSettings = null,
  securitySettings = null,
  cleanupSettings = null,
  maintenanceStatus = null,
  timeoutSettings = null,
  runtimeSettings = null,
  generalSettings = null,
  announcements = [],
  emailAvailable = false
) {
  return `
    ${renderGeneralSettingsPanel(generalSettings)}
    ${renderAnnouncementsAdminPanel(announcements, emailAvailable)}
    ${renderSmtpSettingsPanel(smtpSettings)}
    ${renderEmailTemplatesPanel()}
    ${renderSecuritySettingsPanel(securitySettings)}
    ${renderCleanupSettingsPanel(cleanupSettings)}

    ${renderTimeoutsSettingsPanel(timeoutSettings)}
    ${renderRuntimeSettingsPanel(runtimeSettings)}

    ${renderMaintenanceStatusPanel(maintenanceStatus)}
  `;
}
