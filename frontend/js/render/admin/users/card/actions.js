import { t } from "../../../../i18n/index.js";
import { html } from "../../utils.js";
import { getSmtpDisabledAttrs } from "./helpers.js";

export function renderUserActions(u, { isActive, isEmailVerified }, emailAvailable = true) {
  return `
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
            ${getSmtpDisabledAttrs(emailAvailable)}>
            ${t("admin.users.btn_send_invitation")}
          </button>

          <button class="btn" data-action="create-user-password-reset-link" data-id="${html(u.id)}">
            ${t("admin.users.btn_copy_reset")}
          </button>

          <button class="btn" data-action="send-user-password-reset-email" data-id="${html(u.id)}"
            ${getSmtpDisabledAttrs(emailAvailable)}>
            ${t("admin.users.btn_send_reset")}
          </button>
        </div>

        <div class="admin-action-group admin-action-group--danger">
          <span class="admin-action-label">${t("admin.users.action_group_danger")}</span>
          <button class="btn btn-danger" data-action="delete-user" data-id="${html(u.id)}">
            ${t("admin.users.btn_delete")}
          </button>
        </div>
      </div>`;
}
