import { t } from "../../i18n/index.js";
import { hideMainApp, showMainApp } from "./layout.js";

export { showMainApp };
export { renderSetupForm, renderLoginForm } from "./login.js";
export { renderAcceptInvitationForm, renderPasswordResetForm, renderInvalidToken } from "./tokens.js";

export function renderForcedPasswordChangeForm() {
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.forced_password_title")}</h2>
          <p class="muted">${t("auth.forced_password_subtitle")}</p>
        </div>
      </div>

      <form id="forced-password-change-form" class="form-grid">
        <label>
          <span>${t("auth.field.temp_password")}</span>
          <input type="password" name="current_password" required autocomplete="current-password" />
        </label>

        <label>
          <span>${t("auth.field.new_password")}</span>
          <input type="password" name="new_password" required minlength="8" autocomplete="new-password" />
        </label>

        <label>
          <span>${t("auth.field.confirm_new_password")}</span>
          <input type="password" name="new_password_confirm" required minlength="8" autocomplete="new-password" />
        </label>

        <button type="submit" class="btn btn-primary">
          ${t("auth.action.change_password")}
        </button>
      </form>
    </section>
  `;
}

export function renderMagicLoginRequestForm() {
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.magic_login_title")}</h2>
          <p class="muted">${t("auth.magic_login_subtitle")}</p>
        </div>
      </div>

      <form id="magic-login-request-form" class="form-grid">
        <label>
          <span>${t("auth.field.email")}</span>
          <input type="email" name="email" required autocomplete="username" />
        </label>

        <button type="submit" class="btn btn-primary">
          ${t("auth.action.send_login_link")}
        </button>

        <button type="button" class="btn" id="back-to-login-btn">
          ${t("auth.action.back_to_login")}
        </button>
      </form>
    </section>
  `;
}

export function renderMagicLoginProcessing() {
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.magic_login_processing_title")}</h2>
          <p class="muted">${t("auth.magic_login_processing_text")}</p>
        </div>
      </div>
    </section>
  `;
}

export function renderEmailVerificationProcessing() {
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.email_verification_title")}</h2>
          <p class="muted">${t("auth.email_verification_subtitle")}</p>
        </div>
      </div>
    </section>
  `;
}
