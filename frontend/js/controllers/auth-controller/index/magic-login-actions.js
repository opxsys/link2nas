import { state } from "../../../state.js";
import { showAppMessage } from "../../../utils.js";
import { t } from "../../../i18n/index.js";
import { requestMagicLogin } from "../../../api.js";
import { renderLoginForm, renderMagicLoginRequestForm } from "../../../render/auth.js";

export function bindMagicLoginAuthEvents({ bindAuthEvents }) {
  document.getElementById("show-magic-login-btn")?.addEventListener("click", () => {
    renderMagicLoginRequestForm();
    bindAuthEvents();
  });

  document.getElementById("magic-login-request-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const form = event.target;
    const email = String(form.email?.value || "").trim();

    if (!email) {
      showAppMessage(t("auth.error.email_required"), "error");
      return;
    }

    try {
      const result = await requestMagicLogin(email);
      showAppMessage(
        result.message || t("auth.magic_login_sent"),
        "success"
      );
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
      bindAuthEvents();
    } catch (error) {
      showAppMessage(error.message || t("auth.error.magic_login_send_failed"), "error");
    }
  });
}
