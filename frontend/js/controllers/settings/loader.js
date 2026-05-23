import { state } from "../../state.js";
import {
  listProviders,
  listDestinations,
  getMe,
  listNotificationConfigs,
  listNotificationRules,
  listUserApiKeys,
  getMyIntegrationSettings,
} from "../../api.js";
import {
  renderSettingsPanel,
  renderProvidersPanel,
  renderDestinationsPanel,
} from "../../render/settings.js";
import { renderCreateJobForm } from "../../render/forms.js";
import { renderProwlarrPanel } from "../../render/prowlarr.js";
import { applyCurrentUserTheme } from "../../core/theme.js";
import { loadAndRenderBanner } from "../announcements-controller.js";
import { updateProwlarrNavVisibility } from "../navigation-controller.js";
import { loadEspace } from "./espace.js";

export async function loadSettings() {
  const [
    providers,
    destinations,
    me,
    notificationConfigs,
    notificationRules,
    apiKeys,
    integrationSettings,
  ] = await Promise.all([
    listProviders(),
    listDestinations(),
    getMe(),
    listNotificationConfigs(),
    listNotificationRules(),
    listUserApiKeys(),
    getMyIntegrationSettings(),
  ]);

  state.providers = providers;
  state.destinations = destinations;
  state.currentUser = me;
  applyCurrentUserTheme(me);
  state.notificationConfigs = notificationConfigs;
  state.notificationRules = notificationRules;
  state.userApiKeys = apiKeys;
  state.integrationSettings = integrationSettings;

  const settingsData = {
    providers,
    destinations,
    notificationConfigs,
    notificationRules,
    apiKeys,
    integrationSettings,
  };

  if (typeof renderSettingsPanel === "function") {
    renderSettingsPanel(settingsData, me);
  } else {
    renderProvidersPanel(providers);
    renderDestinationsPanel(destinations);
  }

  const settingsContainer = document.getElementById("settings-panel");
  if (settingsContainer) {
    settingsContainer.removeEventListener("settings-tab-change", onSettingsTabChange);
    settingsContainer.addEventListener("settings-tab-change", onSettingsTabChange);
  }

  const activeTab = localStorage.getItem("settings_tab");
  if (activeTab === "espace") {
    await loadEspace();
  }

  renderCreateJobForm();
  updateProwlarrNavVisibility();

  if (state.activePage === "prowlarr") {
    renderProwlarrPanel();
  }

  await loadAndRenderBanner();
}

export async function onSettingsTabChange(event) {
  if (event.detail?.tab === "espace") {
    await loadEspace();
  }
}
