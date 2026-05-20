import { t } from "../../i18n/index.js";
import {
  VALID_SETTINGS_TABS,
  getActiveSettingsTab,
  setActiveSettingsTab,
  setActiveNotificationSubtab,
} from "./utils.js";
import { renderAccountPanelHtml } from "./account.js";
import { renderApiKeysHtml } from "./api-keys.js";
import { renderProwlarrSettingsHtml } from "./prowlarr.js";
import { renderEspacePanel } from "./espace.js";
import { renderNotificationsHtml, updateNotificationChannelFields } from "./notifications.js";
import { renderProvidersHtml } from "./providers.js";
import { renderDestinationsHtml, updateDestinationFields } from "./destinations.js";

export { renderProvidersPanel, fillProviderForm } from "./providers.js";
export { renderDestinationsPanel, updateDestinationFields, fillDestinationForm } from "./destinations.js";
export { renderEspaceContent } from "./espace.js";
export {
  updateNotificationChannelFields,
  resetNotificationChannelForm,
  fillNotificationChannelForm,
  resetNotificationRuleForm,
  fillNotificationRuleForm,
  updateNotificationFields,
  resetNotificationForm,
  fillNotificationConfigForm,
} from "./notifications.js";

export function renderSettingsPanel(data = {}, me = null) {
  const container = document.getElementById("settings-panel");
  if (!container) return;

  const providers = Array.isArray(data.providers) ? data.providers : [];
  const destinations = Array.isArray(data.destinations) ? data.destinations : [];
  const notificationConfigs = Array.isArray(data.notificationConfigs)
    ? data.notificationConfigs
    : [];
  const notificationRules = Array.isArray(data.notificationRules)
    ? data.notificationRules
    : [];
  const apiKeys = Array.isArray(data.apiKeys) ? data.apiKeys : [];
  const integrationSettings = data.integrationSettings || {};
  const canUseLocalSpace = Boolean(me?.can_use_local_space);

  let activeTab = getActiveSettingsTab();
  if (activeTab === "espace" && !canUseLocalSpace) {
    activeTab = "account";
    setActiveSettingsTab("account");
  }

  const tabBtn = (key) =>
    `<button class="admin-tab${activeTab === key ? " is-active" : ""}" data-settings-tab="${key}">${t(`settings.tabs.${key}`)}</button>`;

  const panel = (key, content) =>
    `<div data-settings-panel="${key}"${activeTab !== key ? " hidden" : ""}>${content}</div>`;

  container.innerHTML = `
    <div class="admin-tabs">
      ${tabBtn("account")}
      ${tabBtn("providers")}
      ${tabBtn("destinations")}
      ${tabBtn("api_keys")}
      ${tabBtn("notifications")}
      ${tabBtn("prowlarr")}
      ${canUseLocalSpace ? tabBtn("espace") : ""}
    </div>

    ${panel("account", renderAccountPanelHtml(me))}
    ${panel("api_keys", renderApiKeysHtml(apiKeys))}
    ${panel("prowlarr", renderProwlarrSettingsHtml(integrationSettings, apiKeys))}
    ${panel("providers", renderProvidersHtml(providers))}
    ${panel("destinations", renderDestinationsHtml(destinations, canUseLocalSpace))}
    ${panel("notifications", renderNotificationsHtml(notificationConfigs, notificationRules, me?.email_sending_available ?? false))}
    ${canUseLocalSpace ? panel("espace", renderEspacePanel()) : ""}
  `;

  updateDestinationFields();
  updateNotificationChannelFields();

  container.querySelectorAll(".admin-tab[data-settings-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.settingsTab;
      if (!VALID_SETTINGS_TABS.includes(tab)) return;
      setActiveSettingsTab(tab);
      container.querySelectorAll("[data-settings-panel]").forEach((p) => {
        p.hidden = p.dataset.settingsPanel !== tab;
      });
      container.querySelectorAll(".admin-tab[data-settings-tab]").forEach((b) => {
        b.classList.toggle("is-active", b.dataset.settingsTab === tab);
      });
      container.dispatchEvent(new CustomEvent("settings-tab-change", { detail: { tab }, bubbles: true }));
    });
  });

  container.querySelectorAll(".settings-subtab[data-notification-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const subtab = btn.dataset.notificationTab;
      setActiveNotificationSubtab(subtab);
      container.querySelectorAll("[data-notification-panel]").forEach((p) => {
        p.hidden = p.dataset.notificationPanel !== subtab;
      });
      container.querySelectorAll(".settings-subtab[data-notification-tab]").forEach((b) => {
        b.classList.toggle("is-active", b.dataset.notificationTab === subtab);
      });
    });
  });
}
