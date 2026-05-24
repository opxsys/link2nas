import { t } from "../../i18n/index.js";

function hideMainApp() {
  const mainApp = document.getElementById("main-app");

  if (mainApp) {
    mainApp.hidden = true;
  }
}

export function renderSetupForm() {
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.setup_title")}</h2>
          <p class="muted">${t("auth.setup_subtitle")}</p>
        </div>
      </div>

      <form id="setup-form" class="form-grid">
        <label>
          <span>${t("auth.field.email")}</span>
          <input type="email" name="email" required autocomplete="username" />
        </label>

        <label>
          <span>${t("auth.field.display_name")}</span>
          <input type="text" name="display_name" autocomplete="name" />
        </label>

        <label>
          <span>${t("auth.field.password")}</span>
          <input type="password" name="password" required minlength="10" autocomplete="new-password" />
        </label>

        <button type="submit" class="btn btn-primary">${t("auth.action.create_super_admin")}</button>
      </form>
    </section>
  `;
}

export function renderLoginForm(emailAvailable = true) {
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.login_title")}</h2>
          <p class="muted">${t("auth.login_subtitle")}</p>
        </div>
      </div>

      <form id="login-form" class="form-grid">
        <label>
          <span>${t("auth.field.email")}</span>
          <input type="email" name="email" required autocomplete="username" />
        </label>

        <label>
          <span>${t("auth.field.password")}</span>
          <input type="password" name="password" required autocomplete="current-password" />
        </label>

        <button type="submit" class="btn btn-primary">${t("auth.action.sign_in")}</button>
        ${emailAvailable
          ? `<button type="button" class="btn" id="show-magic-login-btn">${t("auth.action.magic_login_request")}</button>`
          : ""}
      </form>
    </section>
  `;
}

export function showMainApp() {
  const authPage = document.getElementById("auth-page");
  const mainApp = document.getElementById("main-app");

  if (authPage) {
    authPage.hidden = true;
    authPage.innerHTML = "";
  }

  if (mainApp) {
    mainApp.hidden = false;
  }
}

export function renderAcceptInvitationForm(token, tokenStatus = null) {
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.accept_invitation_title")}</h2>
          <p class="muted">${t("auth.accept_invitation_subtitle")}</p>
          ${
            tokenStatus?.expires_at
              ? `<p class="muted">${t("auth.token_expires_at", { date: new Date(tokenStatus.expires_at).toLocaleString() })}</p>`
              : ""
          }
        </div>
      </div>

      <form id="accept-invitation-form" class="form-grid">
        <input type="hidden" name="token" value="${escapeAuthHtml(token)}" />

        <label>
          <span>${t("auth.field.new_password")}</span>
          <input type="password" name="password" required minlength="8" autocomplete="new-password" />
        </label>

        <label>
          <span>${t("auth.field.confirm_password")}</span>
          <input type="password" name="password_confirm" required minlength="8" autocomplete="new-password" />
        </label>

        <button type="submit" class="btn btn-primary">${t("auth.action.activate_account")}</button>
      </form>
    </section>
  `;
}

export function renderPasswordResetForm(token, tokenStatus = null) {
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.password_reset_title")}</h2>
          <p class="muted">${t("auth.password_reset_subtitle")}</p>
          ${
            tokenStatus?.expires_at
              ? `<p class="muted">${t("auth.token_expires_at", { date: new Date(tokenStatus.expires_at).toLocaleString() })}</p>`
              : ""
          }
        </div>
      </div>

      <form id="password-reset-form" class="form-grid">
        <input type="hidden" name="token" value="${escapeAuthHtml(token)}" />

        <label>
          <span>${t("auth.field.new_password")}</span>
          <input type="password" name="password" required minlength="8" autocomplete="new-password" />
        </label>

        <label>
          <span>${t("auth.field.confirm_password")}</span>
          <input type="password" name="password_confirm" required minlength="8" autocomplete="new-password" />
        </label>

        <button type="submit" class="btn btn-primary">${t("auth.action.reset_password")}</button>
      </form>
    </section>
  `;
}

export function renderInvalidToken(message = null) {
  const resolvedMessage = message || t("auth.invalid_token_message");
  const container = document.getElementById("auth-page");
  hideMainApp();

  container.hidden = false;
  container.innerHTML = `
    <section class="card">
      <div class="section-header">
        <div>
          <h2>${t("auth.invalid_token_title")}</h2>
          <p class="muted">${escapeAuthHtml(resolvedMessage)}</p>
        </div>
      </div>

      <button type="button" class="btn btn-primary" id="back-to-login-btn">
        Retour à la connexion
      </button>
    </section>
  `;
}

function escapeAuthHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

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
