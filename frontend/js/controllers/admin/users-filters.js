import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { renderUserCardList } from "../../render/admin.js";

export function getFilteredAdminUsers(users, query, filter) {
  const q = (query || "").toLowerCase().trim();
  const now = new Date();

  return users.filter((u) => {
    if (q) {
      const matchText =
        (u.email || "").toLowerCase().includes(q) ||
        (u.display_name || "").toLowerCase().includes(q) ||
        (u.role || "").toLowerCase().includes(q);
      if (!matchText) return false;
    }

    switch (filter) {
      case "active":           return Boolean(u.is_active);
      case "disabled":         return !u.is_active;
      case "super-admin":      return Boolean(u.is_super_admin);
      case "email-unverified": return !u.email_verified;
      case "expired":          return Boolean(u.account_expires_at) && new Date(u.account_expires_at) < now;
      default:                 return true;
    }
  });
}

export function bindAdminUsersFilters() {
  const search = document.getElementById("admin-users-search");
  const chips  = document.querySelectorAll("[data-admin-users-filter]");
  const list   = document.querySelector('[data-admin-panel="users"] .admin-users-list');
  const badge  = document.querySelector('[data-admin-panel="users"] .admin-section-title .badge');
  if (!search || !list) return;

  function applyFilter() {
    const query  = search.value;
    const active = document.querySelector("[data-admin-users-filter].is-active");
    const filter = active?.dataset.adminUsersFilter || "all";
    const filtered = getFilteredAdminUsers(state.users || [], query, filter);
    const emailAvail = !!(state.smtpSettings?.enabled && state.smtpSettings?.host && state.smtpSettings?.port && state.smtpSettings?.from_email);

    list.innerHTML = filtered.length
      ? renderUserCardList(filtered, emailAvail)
      : `<div class="empty-state">${t("admin.users.empty_filtered")}</div>`;

    if (badge) {
      badge.textContent = `${filtered.length} ${filtered.length > 1 ? t("admin.users.count_plural") : t("admin.users.count_singular")}`;
    }
  }

  search.addEventListener("input", applyFilter);

  chips.forEach((chip) => {
    chip.addEventListener("click", () => {
      chips.forEach((c) => c.classList.remove("is-active"));
      chip.classList.add("is-active");
      applyFilter();
    });
  });
}
