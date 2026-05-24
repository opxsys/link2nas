import { t } from "../../../../i18n/index.js";
import { renderNotificationConfigOptions } from "../channel-helpers.js";

export function renderNotificationRuleForm(notificationConfigs) {
  return `
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
  `;
}
