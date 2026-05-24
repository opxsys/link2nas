import { t } from "../../../../i18n/index.js";
import { html, toInputDateTime } from "../../utils.js";

export function renderUserEditForms(u, { isActive, isSuperAdmin, isEmailVerified }) {
  return `
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
      </div>`;
}
