import { t } from "../../i18n/index.js";
import { hideMainApp } from "./layout.js";

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
