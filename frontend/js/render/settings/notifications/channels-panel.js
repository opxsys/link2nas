import { t } from "../../../i18n/index.js";
import { html, formatNotificationChannel } from "../utils.js";
import {
  renderNotificationChannelFields,
  renderNotificationChannelDetails,
} from "./channel-helpers.js";

export function renderNotificationChannelsPanel({ activeSubtab, notificationConfigs, emailAvailable }) {
  return `
    <div data-notification-panel="channels"${activeSubtab !== "channels" ? " hidden" : ""}>
    <section class="detail-block">
      <h3>${t("settings.notifications.channels_title")}</h3>

      <form id="notification-channel-form" class="form-grid">
        <input type="hidden" name="config_id" />

        <label>
          <span>${t("settings.notifications.channel_name")}</span>
          <input name="name" placeholder="${t("settings.notifications.channel_name_placeholder")}" required />
        </label>

        <label>
          <span>${t("settings.notifications.channel_type")}</span>
          <select name="channel" id="notification-channel" required>
            <option value="email" ${!emailAvailable ? "disabled" : ""}>${emailAvailable ? "Email" : `Email (${t("email.sending_not_configured")})`}</option>
            <option value="gotify">Gotify</option>
            <option value="webhook">Webhook</option>
          </select>
        </label>

        ${renderNotificationChannelFields()}

        <div class="notification-channel-form-footer">
          <div class="notification-channel-form-flags">
            <label class="checkbox-row">
              <input type="checkbox" name="is_enabled" checked />
              <span>${t("settings.notifications.channel_enabled")}</span>
            </label>
            <label class="checkbox-row">
              <input type="checkbox" name="is_default" />
              <span>${t("settings.notifications.channel_default")}</span>
            </label>
          </div>
          <div class="form-actions notification-channel-form-actions">
            <button type="submit" class="btn btn-primary">${t("settings.notifications.save_channel")}</button>
            <button type="button" class="btn" data-settings-action="test-notification-channel-form">
              ${t("settings.notifications.test_channel")}
            </button>
            <button type="button" class="btn" data-settings-action="reset-notification-channel-form">
              ${t("common.reset")}
            </button>
            <button type="button" class="btn" data-settings-action="cancel-notification-channel-edit" hidden>
              ${t("common.cancel")}
            </button>
          </div>
        </div>
      </form>

      <div class="settings-subsection-header">
        <h3>${t("settings.notifications.configured_channels_title")}</h3>
      </div>

      <div class="settings-list notification-channel-list">
        ${
          notificationConfigs.length
            ? notificationConfigs.map((cfg) => `
                <article class="job-card notification-channel-card">
                  <div class="notification-channel-main">
                    <div class="notification-channel-title-row">
                      <strong>${html(cfg.name)}</strong>
                      ${cfg.is_enabled
                        ? `<span class="meta-pill is-success">${t("settings.notifications.badge_enabled")}</span>`
                        : `<span class="meta-pill is-muted">${t("settings.notifications.badge_disabled")}</span>`
                      }
                      ${cfg.is_default ? `<span class="meta-pill">${t("settings.notifications.badge_default")}</span>` : ""}
                    </div>

                    <div class="notification-channel-meta">
                      <span class="meta-pill">${html(formatNotificationChannel(cfg.channel))}</span>
                    </div>

                    <div class="notification-channel-details">
                      ${renderNotificationChannelDetails(cfg)}
                    </div>
                  </div>

                  <div class="notification-channel-actions inline-actions">
                    <div class="notification-channel-toggles">
                      <label class="notification-channel-toggle">
                        <input
                          type="checkbox"
                          data-settings-action="toggle-notification-channel-enabled"
                          data-notification-config-id="${html(cfg.id)}"
                          ${cfg.is_enabled ? "checked" : ""}
                        />
                        <span>${t("settings.notifications.badge_enabled")}</span>
                      </label>
                      <label class="notification-channel-toggle">
                        <input
                          type="checkbox"
                          data-settings-action="set-notification-channel-default"
                          data-notification-config-id="${html(cfg.id)}"
                          ${cfg.is_default ? "checked" : ""}
                        />
                        <span>${t("settings.notifications.badge_default")}</span>
                      </label>
                    </div>
                    <button type="button" class="btn" data-settings-action="edit-notification-channel" data-notification-config-id="${html(cfg.id)}">
                      ${t("common.edit")}
                    </button>
                    <button type="button" class="btn" data-settings-action="test-stored-notification-channel" data-notification-config-id="${html(cfg.id)}">
                      ${t("common.test")}
                    </button>
                    <button type="button" class="btn btn-danger" data-settings-action="delete-notification-channel" data-notification-config-id="${html(cfg.id)}">
                      ${t("common.delete")}
                    </button>
                  </div>
                </article>
              `).join("")
            : `<p class="muted">${t("settings.notifications.empty_channels")}</p>`
        }
      </div>
    </section>
    </div>
  `;
}
