import { t } from "../../i18n/index.js";
import { hideMainApp, escapeAuthHtml } from "./layout.js";

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
