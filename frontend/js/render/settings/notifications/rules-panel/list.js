import { t } from "../../../../i18n/index.js";
import { renderNotificationRuleCard } from "./card.js";

export function renderNotificationRuleList(notificationRules, notificationConfigs) {
  return `
      <div class="settings-list notification-rule-list">
        ${
          notificationRules.length
            ? notificationRules.map((rule) => renderNotificationRuleCard(rule, notificationConfigs)).join("")
            : `<p class="muted">${t("settings.notifications.empty_rules")}</p>`
        }
      </div>
  `;
}
