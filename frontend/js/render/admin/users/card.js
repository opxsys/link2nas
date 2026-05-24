import { formatDate } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { html, toInputDateTime, renderStatusBadge } from "../utils.js";

export function renderUserCard(u, emailAvailable = true) {
  const isActive = Boolean(u.is_active);
  const isSuperAdmin = Boolean(u.is_super_admin);
  const isEmailVerified = Boolean(u.email_verified);
  const canUseLocalSpace = Boolean(u.can_use_local_space);

  return `
    <article class="admin-user-card" data-user-id="${html(u.id)}">
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

      </div>

      <div class="admin-user-actions">
        <div class="admin-action-group">
          <span class="admin-action-label">${t("admin.users.action_group_account")}</span>

          <button class="btn admin-user-edit-toggle" data-action="toggle-user-edit" data-id="${html(u.id)}">
            ${t("admin.users.edit_summary")}
          </button>

          ${
            isActive
              ? `<button class="btn" data-action="disable-user" data-id="${html(u.id)}">${t("admin.users.btn_disable")}</button>`
              : `<button class="btn" data-action="enable-user" data-id="${html(u.id)}">${t("admin.users.btn_enable")}</button>`
          }

          ${
            !isEmailVerified
              ? `<button class="btn" data-action="verify-user-email" data-id="${html(u.id)}">${t("admin.users.btn_verify_email")}</button>`
              : ""
          }
        </div>

        <div class="admin-action-group">
          <span class="admin-action-label">${t("admin.users.action_group_access")}</span>

          <button class="btn" data-action="create-user-invitation" data-id="${html(u.id)}">
            ${t("admin.users.btn_copy_invitation")}
          </button>

          <button class="btn" data-action="send-user-invitation-email" data-id="${html(u.id)}"
            ${!emailAvailable ? `disabled title="${t("email.smtp_configure_hint")}"` : ""}>
            ${t("admin.users.btn_send_invitation")}
          </button>

          <button class="btn" data-action="create-user-password-reset-link" data-id="${html(u.id)}">
            ${t("admin.users.btn_copy_reset")}
          </button>

          <button class="btn" data-action="send-user-password-reset-email" data-id="${html(u.id)}"
            ${!emailAvailable ? `disabled title="${t("email.smtp_configure_hint")}"` : ""}>
            ${t("admin.users.btn_send_reset")}
          </button>
        </div>

        <div class="admin-action-group admin-action-group--danger">
          <span class="admin-action-label">${t("admin.users.action_group_danger")}</span>
          <button class="btn btn-danger" data-action="delete-user" data-id="${html(u.id)}">
            ${t("admin.users.btn_delete")}
          </button>
        </div>
      </div>

      <div class="admin-user-edit-content" hidden>
        <form class="form-grid user-edit-form" data-user-id="${html(u.id)}">
          <label>
            <span>${t("admin.users.form_email")}</span>
            <input name="email" type="email" value="${html(u.email)}" required />
          </label>

          <label>
            <span>${t("admin.users.form_name")}</span>
            <input name="display_name" value="${html(u.display_name || "")}" />
          </label>

          <label>
            <span>${t("admin.users.form_preferred_language")}</span>
            <select name="preferred_language">
              <option value="en" ${(!u.preferred_language || u.preferred_language === "en") ? "selected" : ""}>${t("settings.account.language_en")}</option>
              <option value="fr" ${u.preferred_language === "fr" ? "selected" : ""}>${t("settings.account.language_fr")}</option>
            </select>
          </label>

          <div class="admin-form-grid-2">
            <label>
              <span>${t("admin.users.form_valid_from")}</span>
              <input type="datetime-local" name="valid_from" value="${html(toInputDateTime(u.valid_from))}" />
            </label>

            <label>
              <span>${t("admin.users.form_expires")}</span>
              <input type="datetime-local" name="account_expires_at" value="${html(toInputDateTime(u.account_expires_at))}" />
            </label>
          </div>

          <div class="admin-checkbox-grid">
            <label class="checkbox-row">
              <input type="checkbox" name="is_super_admin" ${isSuperAdmin ? "checked" : ""} />
              <span>${t("admin.users.form_super_admin")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="is_active" ${isActive ? "checked" : ""} />
              <span>${t("admin.users.form_active")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="email_verified" ${isEmailVerified ? "checked" : ""} />
              <span>${t("admin.users.form_email_verified")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="can_use_local_space" ${Boolean(u.can_use_local_space) ? "checked" : ""} />
              <span>${t("admin.users.form_can_use_local_space")}</span>
            </label>
          </div>

          <button type="submit" class="btn btn-primary">${t("admin.users.form_update")}</button>
        </form>

        <form class="form-grid user-password-form admin-password-reset-box" data-user-id="${html(u.id)}">
          <h4>${t("admin.users.password_reset_title")}</h4>
          <p class="muted">${t("admin.users.password_reset_hint")}</p>

          <label>
            <span>${t("admin.users.password_reset_label")}</span>
            <input name="password" type="password" minlength="8" required />
          </label>

          <button type="submit" class="btn">${t("admin.users.password_reset_submit")}</button>
        </form>
      </div>
    </article>
  `;
}
