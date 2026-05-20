import { t } from "../../i18n/index.js";
import { html } from "./utils.js";

function renderEmailStatus(me) {
  const isEmailVerified = Boolean(me?.email_verified);

  return `
    <article class="job-card">
      <strong>${t("settings.account.email_validation_title")}</strong>

      <div class="muted">
        ${t("settings.account.current_address")} : ${html(me?.email || "—")}
      </div>

      <div style="margin-top: 8px;">
        ${
          isEmailVerified
            ? `<span class="badge badge-ready">${t("settings.account.email_verified")}</span>`
            : `<span class="badge badge-failed">${t("settings.account.email_not_verified")}</span>`
        }
      </div>

      ${
        !isEmailVerified
          ? me?.email_sending_available
            ? `
              <p class="muted" style="margin-top: 8px;">
                ${t("settings.account.email_verification_hint")}
              </p>

              <button type="button" class="btn" id="request-email-verification-btn">
                ${t("settings.account.send_verification_email")}
              </button>
            `
            : `
              <p class="muted" style="margin-top: 8px;">
                ${t("email.smtp_configure_hint")}
              </p>
            `
          : ""
      }
    </article>
  `;
}

export function renderAccountPanelHtml(me) {
  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.account.title")}</h2>
        <p class="muted">${t("settings.account.subtitle")}</p>
      </div>
    </div>

    <form id="my-profile-form" class="form-grid">
      <label>
        <span>${t("settings.account.email_label")}</span>
        <input name="email" type="email" value="${html(me?.email || "")}" required />
        <p class="muted">${t("settings.account.email_hint")}</p>
      </label>

      <label>
        <span>${t("settings.account.display_name_label")}</span>
        <input name="display_name" value="${html(me?.display_name || "")}" />
      </label>

      <label>
        <span>${t("settings.account.language_label")}</span>
        <select name="preferred_language">
          <option value="en" ${(!me?.preferred_language || me?.preferred_language === "en") ? "selected" : ""}>${t("settings.account.language_en")}</option>
          <option value="fr" ${me?.preferred_language === "fr" ? "selected" : ""}>${t("settings.account.language_fr")}</option>
        </select>
      </label>

      <label>
        <span>${t("settings.account.theme_label")}</span>
        <select name="ui_theme">
          <option value="auto" ${(!me?.ui_theme || me?.ui_theme === "auto") ? "selected" : ""}>${t("settings.account.theme_auto")}</option>
          <option value="light" ${me?.ui_theme === "light" ? "selected" : ""}>${t("settings.account.theme_light")}</option>
          <option value="night" ${me?.ui_theme === "night" ? "selected" : ""}>${t("settings.account.theme_night")}</option>
          <option value="high_contrast" ${me?.ui_theme === "high_contrast" ? "selected" : ""}>${t("settings.account.theme_high_contrast")}</option>
          <option value="colorblind" ${me?.ui_theme === "colorblind" ? "selected" : ""}>${t("settings.account.theme_colorblind")}</option>
        </select>
      </label>

      <label class="checkbox-row">
        <input
          type="checkbox"
          name="receive_application_emails"
          ${Boolean(me?.receive_application_emails) ? "checked" : ""}
        />
        <span>${t("settings.account.receive_application_emails_label")}</span>
      </label>
      <p class="muted">${t("settings.account.receive_application_emails_hint")}</p>
      ${me?.receive_application_emails && !me?.email_verified ? `<p class="muted">${t("settings.account.email_unverified_for_announcements")}</p>` : ""}

      <button class="btn btn-primary">${t("settings.account.save_profile")}</button>
    </form>

    ${renderEmailStatus(me)}

    ${
      me?.single_user_mode
        ? `
          <article class="job-card">
            <strong>${t("settings.account.single_user_title")}</strong>
            <p class="muted">${t("settings.account.single_user_password_disabled")}</p>
            <p class="muted">${t("settings.account.single_user_access_hint")}</p>
          </article>
        `
        : `
          <form id="change-password-form" class="form-grid">
            <label>
              <span>${t("settings.account.current_password_label")}</span>
              <input name="current_password" type="password" required />
            </label>

            <label>
              <span>${t("settings.account.new_password_label")}</span>
              <input name="new_password" type="password" minlength="8" required />
            </label>

            <button class="btn">${t("settings.account.change_password")}</button>
          </form>
        `
    }
  `;
}
