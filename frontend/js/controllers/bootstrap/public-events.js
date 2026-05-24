import { state } from "../../state.js";
import { getSetupStatus } from "../../api.js";
import { renderSetupForm, renderLoginForm } from "../../render/auth.js";
import { bindAuthEvents } from "../auth-controller.js";
import {
  renderStaticTexts,
  rerenderAppForLanguageChange,
  closeNavDrawer,
} from "../navigation-controller.js";

let publicEventsBound = false;

export function bindPublicEvents() {
  if (publicEventsBound) return;
  publicEventsBound = true;

  document.getElementById("language-switch")?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-lang]");
    if (!button) return;

    const lang = button.dataset.lang;
    if (!lang || lang === state.language) return;

    closeNavDrawer();

    state.language = lang;
    localStorage.setItem("link2nas_language", lang);

    if (state.currentUser) {
      await rerenderAppForLanguageChange();
      return;
    }

    renderStaticTexts();

    const setupStatus = await getSetupStatus();
    if (setupStatus.setup_required) {
      renderSetupForm();
    } else {
      renderLoginForm(state.appInfo?.email_sending_available ?? true);
    }

    bindAuthEvents();
  });
}
