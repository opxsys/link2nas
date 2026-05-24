import { renderUserCardList } from "./users.js";
import { renderAdminUsersPanel } from "./users-panel.js";
import { renderAntiAbuseSection } from "./anti-abuse.js";
import { renderAnnouncementForm, renderAnnouncementTrackingPanel, renderAnnouncementsAdminPanel } from "./announcements.js";
import { renderAdminSectionPlaceholders } from "./sections-placeholders.js";
import { renderAdminTabs } from "./tabs.js";
import { renderAdminPageHeader, renderSingleUserAdminWarning } from "./page-layout.js";

export { renderUserCardList, renderAntiAbuseSection, renderAnnouncementForm, renderAnnouncementTrackingPanel, renderAnnouncementsAdminPanel };



export function renderUsersPanel(
  users = [],
  smtpSettings = null,
  securitySettings = null,
  cleanupSettings = null,
  maintenanceStatus = null,
  timeoutSettings = null,
  runtimeSettings = null,
  options = {},
  generalSettings = null,
  announcements = []
) {
  const container = document.getElementById("users-panel");
  if (!container) return;

  const singleUserMode = Boolean(options.singleUserMode);
  const emailAvailable = Boolean(options.emailAvailable !== false);

  const usersPanel = renderAdminUsersPanel({ users, emailAvailable, singleUserMode });

  container.innerHTML = `
    <div class="admin-page">
      ${renderAdminPageHeader({ singleUserMode })}

      ${renderAdminTabs({ singleUserMode })}

      ${renderSingleUserAdminWarning({ singleUserMode })}

      ${usersPanel}
      ${renderAdminSectionPlaceholders(
        smtpSettings,
        securitySettings,
        cleanupSettings,
        maintenanceStatus,
        timeoutSettings,
        runtimeSettings,
        generalSettings,
        announcements,
        emailAvailable
      )}
    </div>
  `;
}
