import { t } from "../../../../i18n/index.js";
import {
  html,
  formatNotificationChannel,
  formatNotificationSeverity,
  formatEventTypeLabel,
} from "../../utils.js";

export function renderNotificationRuleCard(rule, notificationConfigs) {
  const cfg = notificationConfigs.find((item) => item.id === rule.config_id);
  const cfgLabel = cfg
    ? `${cfg.name} — ${formatNotificationChannel(cfg.channel)}`
    : t("settings.notifications.channel_not_found");
  const cfgDisabled = cfg && !cfg.is_enabled;

  return `
                  <article class="job-card notification-rule-card">
                    <div class="notification-rule-main">
                      <div class="notification-rule-title-row">
                        <strong>${html(rule.name)}</strong>
                        ${rule.is_enabled
                          ? `<span class="meta-pill is-success">${t("settings.notifications.badge_enabled")}</span>`
                          : `<span class="meta-pill is-muted">${t("settings.notifications.badge_disabled")}</span>`
                        }
                      </div>

                      <div class="notification-rule-meta">
                        <span class="meta-pill${cfgDisabled ? " is-muted" : ""}">
                          ${t("settings.notifications.meta_channel")}: ${html(cfgLabel)}${cfgDisabled ? ` (${t("settings.notifications.badge_disabled")})` : ""}
                        </span>
                        <span class="meta-pill">${t("settings.notifications.meta_severity")}: ${html(formatNotificationSeverity(rule.severity_min))}</span>
                        <span class="meta-pill">${t("settings.notifications.meta_rate_limit")}: ${html(String(rule.rate_limit_per_hour))}/h</span>
                        <span class="meta-pill">${t("settings.notifications.meta_scope")}: ${html(rule.scope || "user")}</span>
                      </div>

                      <div class="notification-rule-events">
                        ${Array.isArray(rule.event_types) && rule.event_types.length
                          ? rule.event_types.map((type) => `<span class="meta-pill">${html(formatEventTypeLabel(type))}</span>`).join("")
                          : `<span class="meta-pill is-muted">${t("settings.notifications.meta_all_events")}</span>`
                        }
                      </div>
                    </div>

                    <div class="notification-rule-actions inline-actions">
                      <div class="notification-rule-toggles">
                        <label class="notification-rule-toggle">
                          <input
                            type="checkbox"
                            data-settings-action="toggle-notification-rule-enabled"
                            data-notification-rule-id="${html(rule.id)}"
                            ${rule.is_enabled ? "checked" : ""}
                          />
                          <span>${t("settings.notifications.badge_enabled")}</span>
                        </label>
                      </div>
                      <button type="button" class="btn" data-settings-action="edit-notification-rule" data-notification-rule-id="${html(rule.id)}">
                        ${t("common.edit")}
                      </button>
                      <button type="button" class="btn btn-danger" data-settings-action="delete-notification-rule" data-notification-rule-id="${html(rule.id)}">
                        ${t("common.delete")}
                      </button>
                    </div>
                  </article>
                `;
}
