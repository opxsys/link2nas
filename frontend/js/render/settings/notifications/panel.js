import { t } from "../../../i18n/index.js";
import { getActiveNotificationSubtab } from "../utils.js";
import { renderNotificationChannelsPanel } from "./channels-panel.js";
import { renderNotificationRulesPanel } from "./rules-panel.js";

export function renderNotificationsHtml(notificationConfigs = [], notificationRules = [], emailAvailable = true) {
  const activeSubtab = getActiveNotificationSubtab();
  return `
    <div class="section-header">
      <div>
        <h2>${t("settings.notifications.title")}</h2>
        <p class="muted">${t("settings.notifications.subtitle")}</p>
      </div>
    </div>

    <div id="notification-feedback" hidden></div>

    <div class="settings-subtabs">
      <button class="settings-subtab${activeSubtab === "channels" ? " is-active" : ""}" data-notification-tab="channels">
        ${t("settings.notifications.tab_channels")}
      </button>
      <button class="settings-subtab${activeSubtab === "rules" ? " is-active" : ""}" data-notification-tab="rules">
        ${t("settings.notifications.tab_rules")}
      </button>
    </div>

    ${renderNotificationChannelsPanel({ activeSubtab, notificationConfigs, emailAvailable })}

    ${renderNotificationRulesPanel({ activeSubtab, notificationConfigs, notificationRules })}
  `;
}
