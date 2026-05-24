import { t } from "../../i18n/index.js";

export function renderAdminTabs({ singleUserMode }) {
  const usersTab = singleUserMode
    ? ""
    : `<button type="button" class="admin-tab is-active" data-admin-tab="users">${t("admin.tab.users")}</button>`;

  return `
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
      </div>`;
}
