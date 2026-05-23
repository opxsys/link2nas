import { state } from "../../state.js";
import { t } from "../../i18n/index.js";
import { saveMyIntegrationSettings } from "../../api.js";
import { showAppMessage } from "../../utils.js";
import { hasConfiguredProwlarr } from "../../render/prowlarr.js";
import { renderPageVisibility } from "../navigation-controller.js";
import { loadSettings } from "./loader.js";

export async function handleProwlarrSubmit(form) {
  if (form.id === "prowlarr-settings-form") {
    const saved = await saveMyIntegrationSettings({
      prowlarr_enabled: Boolean(form.prowlarr_enabled?.checked),
      prowlarr_url: form.prowlarr_url?.value || "",
      prowlarr_open_mode: form.prowlarr_open_mode?.value || "both",
      home_page: form.home_page?.value || "jobs",
    });

    state.integrationSettings = saved;

    if (state.activePage === "prowlarr" && !hasConfiguredProwlarr()) {
      state.activePage = "jobs";
      localStorage.setItem("link2nas_active_page", "jobs");
    }

    showAppMessage(t("messages.settings_prowlarr_saved"), "success");
    await loadSettings();
    renderPageVisibility();
    return true;
  }

  return false;
}
