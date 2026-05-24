import { t } from "../../../../i18n/index.js";
import { renderNotificationRuleForm } from "./form.js";
import { renderNotificationRuleList } from "./list.js";

export function renderNotificationRulesPanel({ activeSubtab, notificationConfigs, notificationRules }) {
  return `
    <div data-notification-panel="rules"${activeSubtab !== "rules" ? " hidden" : ""}>
    <section class="detail-block">
      <h3>${t("settings.notifications.rules_title")}</h3>

      ${
        notificationConfigs.length === 0
          ? `<p class="muted">${t("settings.notifications.rules_no_channel")}</p>`
          : notificationConfigs.every((cfg) => !cfg.is_enabled)
            ? `<p class="muted">${t("settings.notifications.rules_no_active_channel")}</p>`
            : `
      ${renderNotificationRuleForm(notificationConfigs)}

      <div class="settings-subsection-header">
        <h3>${t("settings.notifications.configured_rules_title")}</h3>
      </div>

      ${renderNotificationRuleList(notificationRules, notificationConfigs)}
      `}
    </section>
    </div>
  `;
}
