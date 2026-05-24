import { formatDate } from "../../../../utils.js";
import { t } from "../../../../i18n/index.js";
import { html, renderStatusBadge } from "../../utils.js";

export function renderUserSummary(u, { isActive, isSuperAdmin, isEmailVerified, canUseLocalSpace }) {
  return `
      <div class="admin-user-main">
        <div class="admin-user-header">
          <div class="admin-user-identity">
            <strong class="admin-user-email">${html(u.email)}</strong>
            <span class="muted">${html(u.display_name || t("admin.users.no_display_name"))}</span>
          </div>

          <div class="admin-user-badges">
            ${renderStatusBadge(isActive ? t("admin.users.badge_active") : t("admin.users.badge_disabled"), isActive ? "ready" : "failed")}
            ${isSuperAdmin ? renderStatusBadge(t("admin.users.badge_super_admin"), "premium") : renderStatusBadge(t("admin.users.badge_user"))}
            ${renderStatusBadge(isEmailVerified ? t("admin.users.badge_email_verified") : t("admin.users.badge_email_unverified"), isEmailVerified ? "ready" : "failed")}
            ${canUseLocalSpace ? renderStatusBadge(t("admin.users.badge_local_space"), "ready") : ""}
          </div>
        </div>

        <div class="admin-user-meta">
          <div>
            <span class="muted">${t("admin.users.meta_valid_from")}</span>
            <strong>${u.valid_from ? html(formatDate(u.valid_from)) : "—"}</strong>
          </div>
          <div>
            <span class="muted">${t("admin.users.meta_expires")}</span>
            <strong>${u.account_expires_at ? html(formatDate(u.account_expires_at)) : "—"}</strong>
          </div>
          <div>
            <span class="muted">${t("admin.users.meta_last_login")}</span>
            <strong>${u.last_login_at ? html(formatDate(u.last_login_at)) : "—"}</strong>
          </div>
        </div>

      </div>`;
}
