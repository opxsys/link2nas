import { t } from "../../i18n/index.js";
import { renderUserCard, renderCreateUserBlock } from "./users.js";

export function renderAdminUsersPanel({ users, emailAvailable, singleUserMode }) {
  if (singleUserMode) return "";

  return `
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
}
