import { t } from "../../i18n/index.js";
import { hideMainApp } from "./layout.js";

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
