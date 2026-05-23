import { t } from "../../../i18n/index.js";
import { html, formatNotificationChannel } from "../utils.js";

export function renderNotificationChannelFields() {
  return `
    <div data-notification-channel-field="email">
      <label>
        <span>${t("settings.notifications.email_to")}</span>
        <input name="to_email" type="email" placeholder="${t("settings.notifications.email_to_placeholder")}" />
      </label>
      <p class="muted">
        ${t("settings.notifications.email_to_hint")}
      </p>
    </div>

    <div data-notification-channel-field="gotify">
      <label>
        <span>${t("settings.notifications.gotify_server_url")}</span>
        <input name="gotify_server_url" placeholder="https://gotify.example.com" />
      </label>

      <label>
        <span>${t("settings.notifications.gotify_token")}</span>
        <input name="gotify_token" type="password" placeholder="${t("settings.notifications.gotify_token_placeholder")}" />
      </label>
    </div>

    <div data-notification-channel-field="webhook">
      <label>
        <span>${t("settings.notifications.webhook_url")}</span>
        <input name="webhook_url" placeholder="https://example.com/webhook" />
      </label>

      <label>
        <span>${t("settings.notifications.webhook_method")}</span>
        <select name="webhook_method">
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
        </select>
      </label>

      <label>
        <span>${t("settings.notifications.webhook_headers")}</span>
        <textarea name="webhook_headers" rows="4" placeholder='{"Authorization":"Bearer xxx"}'></textarea>
      </label>
    </div>
  `;
}

export function renderNotificationConfigOptions(notificationConfigs = [], selectedId = "") {
  const activeConfigs = notificationConfigs.filter((cfg) => cfg.is_enabled);
  if (!activeConfigs.length) {
    return `<option value="">${t("settings.notifications.no_channel_option")}</option>`;
  }

  return activeConfigs.map((cfg) => `
    <option value="${html(cfg.id)}" ${cfg.id === selectedId ? "selected" : ""}>
      ${html(cfg.name)} — ${html(formatNotificationChannel(cfg.channel))}
    </option>
  `).join("");
}

export function renderNotificationChannelDetails(cfg) {
  const config = cfg.config || {};
  const channel = String(cfg.channel || "").trim().toLowerCase();
  const row = (labelKey, value) => {
    const safeValue = html(String(value ?? "—"));
    return `<div>
      <span class="notification-channel-detail-label">${t(labelKey)}</span>
      <span class="notification-channel-detail-value" title="${safeValue}">${safeValue}</span>
    </div>`;
  };

  if (channel === "email") {
    return row("settings.notifications.detail_to_email", config.to_email || "—");
  }
  if (channel === "gotify") {
    return row("settings.notifications.detail_server_url", config.server_url || "—");
  }
  if (channel === "webhook") {
    return [
      row("settings.notifications.detail_url", config.url || "—"),
      row("settings.notifications.detail_method", config.method || "POST"),
    ].join("");
  }
  return "";
}
