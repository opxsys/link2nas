import { t } from "../../../i18n/index.js";

export function renderCreateUserBlock() {
  return `
    <details class="admin-section-card admin-create-user-block">
      <summary>
        <span>
          <strong>${t("admin.users.create_title")}</strong>
          <small>${t("admin.users.create_subtitle")}</small>
        </span>
      </summary>

      <form id="user-form" class="form-grid admin-create-user-form">
        <div class="admin-form-grid-2">
          <label>
            <span>${t("admin.users.form_email")}</span>
            <input name="email" type="email" placeholder="email@example.com" required />
          </label>

          <label>
            <span>${t("admin.users.form_name")}</span>
            <input name="display_name" placeholder="${t("admin.users.form_name")}" />
          </label>
        </div>

        <label>
          <span>${t("admin.users.form_creation_mode")}</span>
          <select name="creation_mode" id="user-creation-mode">
            <option value="password">${t("admin.users.mode_password")}</option>
            <option value="invitation">${t("admin.users.mode_invitation")}</option>
          </select>
        </label>

        <label>
          <span>${t("admin.users.form_preferred_language")}</span>
          <select name="preferred_language">
            <option value="en">${t("settings.account.language_en")}</option>
            <option value="fr">${t("settings.account.language_fr")}</option>
          </select>
        </label>

        <label id="user-password-row">
          <span>${t("admin.users.form_password")}</span>
          <input name="password" type="password" placeholder="${t("admin.users.form_password_placeholder")}" minlength="8" required />
        </label>

        <label id="user-force-password-change-row" class="checkbox-row">
          <input type="checkbox" name="force_password_change" checked />
          <span>${t("admin.users.form_force_password_change")}</span>
        </label>

        <div class="admin-form-grid-2">
          <label>
            <span>${t("admin.users.form_valid_from")}</span>
            <input type="datetime-local" name="valid_from" />
          </label>

          <label>
            <span>${t("admin.users.form_expires")}</span>
            <input type="datetime-local" name="account_expires_at" />
          </label>
        </div>

        <div class="admin-checkbox-grid">
          <label class="checkbox-row">
            <input type="checkbox" name="is_super_admin" />
            <span>${t("admin.users.form_super_admin")}</span>
          </label>

          <label class="checkbox-row">
            <input type="checkbox" name="email_verified" />
            <span>${t("admin.users.form_mark_email_verified")}</span>
          </label>

          <label class="checkbox-row">
            <input type="checkbox" name="can_use_local_space" />
            <span>${t("admin.users.form_can_use_local_space")}</span>
          </label>
        </div>

        <button type="submit" class="btn btn-primary">${t("admin.users.btn_create")}</button>
      </form>
    </details>
  `;
}
