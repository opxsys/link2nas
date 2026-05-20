import { state } from "../state.js";
import { showAppMessage } from "../utils.js";
import { t } from "../i18n/index.js";
import {
  handleAdminSubmit,
  handleAdminClick,
  switchAdminTab,
  updateUserCreationModeFields,
  initEmailTemplatesPanel,
  loadAntiAbuseSection,
  loadEmailTemplateIntoPanel,
} from "../controllers/admin-controller.js";

export function bindAdminEvents() {
  document.getElementById("admin-page")?.addEventListener("change", (event) => {
    if (event.target?.id === "user-creation-mode") {
      updateUserCreationModeFields();
    }

    if (
      event.target?.id === "email-template-key-select" ||
      event.target?.id === "email-template-lang-select"
    ) {
      const key = document.getElementById("email-template-key-select")?.value;
      const lang = document.getElementById("email-template-lang-select")?.value;
      if (key && lang) {
        loadEmailTemplateIntoPanel(key, lang);
      }
    }
  });

  document.getElementById("admin-page")?.addEventListener("submit", async (event) => {
    event.preventDefault();

    try {
      await handleAdminSubmit(event.target);
    } catch (error) {
      showAppMessage(error.message || t("messages.admin_action_error"), "error");
    }
  });

  document.getElementById("admin-page")?.addEventListener("click", async (event) => {
    const tabButton = event.target.closest("[data-admin-tab]");
    if (tabButton) {
      state.activeAdminTab = tabButton.dataset.adminTab || "users";
      switchAdminTab(state.activeAdminTab);
      if (state.activeAdminTab === "email-templates") {
        await initEmailTemplatesPanel();
      }
      if (state.activeAdminTab === "security") {
        await loadAntiAbuseSection();
      }
      return;
    }

    const button = event.target.closest("[data-action]");
    if (!button) return;

    try {
      await handleAdminClick(button);
    } catch (error) {
      showAppMessage(error.message || t("messages.admin_action_error"), "error");
    }
  });
}
