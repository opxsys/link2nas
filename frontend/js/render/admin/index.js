import { t } from "../../i18n/index.js";
import { renderUserCardList } from "./users.js";
import { renderAdminUsersPanel } from "./users-panel.js";
import { renderAntiAbuseSection } from "./anti-abuse.js";
import { renderAnnouncementForm, renderAnnouncementTrackingPanel, renderAnnouncementsAdminPanel } from "./announcements.js";
import { renderAdminSectionPlaceholders } from "./sections-placeholders.js";
import { renderAdminTabs } from "./tabs.js";

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
      <div class="section-header admin-page-header">
        <div>
          <h2>${t("admin.page.title")}</h2>
          <p class="muted">
            ${singleUserMode ? t("admin.page.subtitle_single_user") : t("admin.page.subtitle")}
          </p>
        </div>

        ${
          singleUserMode
            ? `<span class="badge badge-warning">${t("settings.account.single_user_title")}</span>`
            : ""
        }
      </div>

      ${renderAdminTabs({ singleUserMode })}

      ${
        singleUserMode
          ? `
            <section class="admin-section-card">
              <div class="admin-section-title">
                <div>
                  <h3>${t("admin.users.single_user_warning_title")}</h3>
                  <p class="muted">${t("admin.users.single_user_warning_text")}</p>
                </div>
              </div>
            </section>
          `
          : ""
      }

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
