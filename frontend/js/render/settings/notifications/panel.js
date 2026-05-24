import { t } from "../../../i18n/index.js";
import {
  html,
  formatNotificationChannel,
  formatNotificationSeverity,
  formatEventTypeLabel,
  getActiveNotificationSubtab,
} from "../utils.js";
import { renderNotificationConfigOptions } from "./channel-helpers.js";
import { renderNotificationChannelsPanel } from "./channels-panel.js";

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

    <div data-notification-panel="rules"${activeSubtab !== "rules" ? " hidden" : ""}>
    <section class="detail-block">
      <h3>${t("settings.notifications.rules_title")}</h3>

      ${
        notificationConfigs.length === 0
          ? `<p class="muted">${t("settings.notifications.rules_no_channel")}</p>`
          : notificationConfigs.every((cfg) => !cfg.is_enabled)
            ? `<p class="muted">${t("settings.notifications.rules_no_active_channel")}</p>`
            : `
      <form id="notification-rule-form" class="form-grid">
        <input type="hidden" name="rule_id" />

        <label>
          <span>${t("settings.notifications.rule_name")}</span>
          <input name="name" placeholder="${t("settings.notifications.rule_name_placeholder")}" required />
        </label>

        <label>
          <span>${t("settings.notifications.rule_channel")}</span>
          <select name="config_id" required>
            ${renderNotificationConfigOptions(notificationConfigs)}
          </select>
        </label>

        <label>
          <span>${t("settings.notifications.rule_severity")}</span>
          <select name="severity_min">
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
            <option value="critical">Critical</option>
          </select>
        </label>

        <fieldset class="detail-block">
          <legend>${t("settings.notifications.rule_event_types")}</legend>

          <div class="notification-event-grid">
            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="job.completed" />
              <span>${t("settings.notifications.event_job_completed")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="job.failed" checked />
              <span>${t("settings.notifications.event_job_failed")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="job.links_ready" />
              <span>${t("settings.notifications.event_job_links_ready")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="job.cancelled" />
              <span>${t("settings.notifications.event_job_cancelled")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="destination.sent" />
              <span>${t("settings.notifications.event_destination_sent")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="destination.failed" checked />
              <span>${t("settings.notifications.event_destination_failed")}</span>
            </label>

            <label class="checkbox-row">
              <input type="checkbox" name="event_type" value="provider.failed" checked />
              <span>${t("settings.notifications.event_provider_failed")}</span>
            </label>
          </div>

          <p class="muted">
            ${t("settings.notifications.event_types_hint")}
          </p>
        </fieldset>

        <label>
          <span>${t("settings.notifications.rule_rate_limit")}</span>
          <input name="rate_limit_per_hour" type="number" min="0" max="1000" value="30" required />
        </label>

        <div class="notification-rule-form-footer">
          <div class="notification-rule-form-flags">
            <label class="checkbox-row">
              <input type="checkbox" name="is_enabled" checked />
              <span>${t("settings.notifications.rule_enabled")}</span>
            </label>
          </div>
          <div class="form-actions notification-rule-form-actions">
            <button type="submit" class="btn btn-primary">${t("settings.notifications.save_rule")}</button>
            <button type="button" class="btn" data-settings-action="reset-notification-rule-form">
              ${t("common.reset")}
            </button>
            <button type="button" class="btn" data-settings-action="cancel-notification-rule-edit" hidden>
              ${t("common.cancel")}
            </button>
          </div>
        </div>
      </form>

      <div class="settings-subsection-header">
        <h3>${t("settings.notifications.configured_rules_title")}</h3>
      </div>

      <div class="settings-list notification-rule-list">
        ${
          notificationRules.length
            ? notificationRules.map((rule) => {
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
              }).join("")
            : `<p class="muted">${t("settings.notifications.empty_rules")}</p>`
        }
      </div>
      `}
    </section>
    </div>
  `;
}
