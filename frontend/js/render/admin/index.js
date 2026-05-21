import { t } from "../../i18n/index.js";
import { renderUserCard, renderCreateUserBlock, renderUserCardList } from "./users.js";
import { renderGeneralSettingsPanel } from "./general.js";
import { renderSmtpSettingsPanel } from "./smtp.js";
import { renderSecuritySettingsPanel } from "./security.js";
import { renderAntiAbuseSection } from "./anti-abuse.js";
import { renderCleanupSettingsPanel } from "./cleanup.js";
import { renderTimeoutsSettingsPanel } from "./timeouts.js";
import { renderMaintenanceStatusPanel } from "./maintenance.js";
import { renderRuntimeSettingsPanel } from "./runtime.js";
import { renderEmailTemplatesPanel } from "./email-templates.js";
import { renderAnnouncementForm, renderAnnouncementTrackingPanel, renderAnnouncementsAdminPanel } from "./announcements.js";

export { renderUserCardList, renderAntiAbuseSection, renderAnnouncementForm, renderAnnouncementTrackingPanel, renderAnnouncementsAdminPanel };


function renderAdminSectionPlaceholders(
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

  const usersTab = singleUserMode
    ? ""
    : `<button type="button" class="admin-tab is-active" data-admin-tab="users">${t("admin.tab.users")}</button>`;

  const usersPanel = singleUserMode
    ? ""
    : `
      <section class="admin-section-card admin-tab-panel" data-admin-panel="users">
        <div class="admin-section-title">
          <div>
            <h3>${t("admin.users.title")}</h3>
            <p class="muted">${t("admin.users.subtitle")}</p>
          </div>
          <span class="badge">${users.length} ${users.length > 1 ? t("admin.users.count_plural") : t("admin.users.count_singular")}</span>
        </div>

        <div id="admin-users-feedback" hidden></div>

        <div class="admin-users-toolbar">
          <input
            id="admin-users-search"
            type="search"
            placeholder="${t("admin.users.search_placeholder")}"
          />
          <div class="admin-users-filters">
            <button type="button" class="filter-chip is-active" data-admin-users-filter="all">${t("admin.users.filter_all")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="active">${t("admin.users.filter_active")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="disabled">${t("admin.users.filter_disabled")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="super-admin">${t("admin.users.filter_super_admin")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="email-unverified">${t("admin.users.filter_email_unverified")}</button>
            <button type="button" class="filter-chip" data-admin-users-filter="expired">${t("admin.users.filter_expired")}</button>
          </div>
        </div>

        ${renderCreateUserBlock()}

        <div class="admin-users-list">
          ${users.length ? users.map((u) => renderUserCard(u, emailAvailable)).join("") : `<div class="empty-state">${t("admin.users.empty")}</div>`}
        </div>
      </section>
    `;

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

      <div class="admin-tabs">
        ${usersTab}
        <button type="button" class="admin-tab" data-admin-tab="general">${t("admin.tab.general")}</button>
        <button type="button" class="admin-tab" data-admin-tab="announcements">${t("admin.tab.announcements")}</button>
        <button type="button" class="admin-tab ${singleUserMode ? "is-active" : ""}" data-admin-tab="maintenance">${t("admin.tab.maintenance")}</button>
        <button type="button" class="admin-tab" data-admin-tab="smtp">${t("admin.tab.smtp")}</button>
        <button type="button" class="admin-tab" data-admin-tab="email-templates">${t("admin.tab.email_templates")}</button>
        <button type="button" class="admin-tab" data-admin-tab="security">${t("admin.tab.security")}</button>
        <button type="button" class="admin-tab" data-admin-tab="timeouts">${t("admin.tab.timeouts")}</button>
        <button type="button" class="admin-tab" data-admin-tab="runtime">${t("admin.tab.runtime")}</button>
        <button type="button" class="admin-tab" data-admin-tab="cleanup">${t("admin.tab.cleanup")}</button>
      </div>

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
