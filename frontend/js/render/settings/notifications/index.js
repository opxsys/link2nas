import { t } from "../../../i18n/index.js";
import {
  html,
  formatNotificationChannel,
  formatNotificationSeverity,
  formatEventTypeLabel,
  getActiveNotificationSubtab,
  setActiveNotificationSubtab,
} from "../utils.js";
import {
  renderNotificationChannelFields,
  renderNotificationConfigOptions,
  renderNotificationChannelDetails,
} from "./channel-helpers.js";

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

export function updateNotificationChannelFields() {
  const select = document.getElementById("notification-channel");
  const channel = select?.value || "email";

  document.querySelectorAll("[data-notification-channel-field]").forEach((field) => {
    field.hidden = field.dataset.notificationChannelField !== channel;
  });
}

export function resetNotificationChannelForm() {
  const form = document.getElementById("notification-channel-form");
  if (!form) return;

  form.reset();
  form.config_id.value = "";
  form.channel.value = "email";
  form.is_enabled.checked = true;
  form.is_default.checked = false;

  if (form.gotify_token) {
    form.gotify_token.placeholder = t("settings.notifications.gotify_token_placeholder");
  }

  if (form.webhook_headers) {
    form.webhook_headers.placeholder = '{"Authorization":"Bearer xxx"}';
  }

  const submit = form.querySelector("button[type='submit']");
  if (submit) submit.textContent = t("settings.notifications.save_channel");

  updateNotificationChannelFields();
}

export function fillNotificationChannelForm(config) {
  const form = document.getElementById("notification-channel-form");
  if (!form || !config) return;

  form.config_id.value = config.id || "";
  form.name.value = config.name || "";
  form.channel.value = config.channel || "email";
  form.is_enabled.checked = Boolean(config.is_enabled);
  form.is_default.checked = Boolean(config.is_default);

  const cfg = config.config || {};

  if (form.to_email) {
    form.to_email.value = cfg.to_email || "";
  }

  if (form.gotify_server_url) {
    form.gotify_server_url.value = cfg.server_url || "";
  }

  if (form.gotify_token) {
    form.gotify_token.value = "";
    form.gotify_token.placeholder = cfg.has_token
      ? t("settings.notifications.gotify_token_saved_hint")
      : t("settings.notifications.gotify_token_placeholder");
  }

  if (form.webhook_url) {
    form.webhook_url.value = cfg.url || "";
  }

  if (form.webhook_method) {
    form.webhook_method.value = cfg.method || "POST";
  }

  if (form.webhook_headers) {
    form.webhook_headers.value = "";
    form.webhook_headers.placeholder = cfg.has_headers
      ? t("settings.notifications.webhook_headers_saved_hint")
      : '{"Authorization":"Bearer xxx"}';
  }

  const submit = form.querySelector("button[type='submit']");
  if (submit) submit.textContent = t("settings.notifications.update_channel");

  const cancelBtn = form.querySelector("[data-settings-action='cancel-notification-channel-edit']");
  if (cancelBtn) cancelBtn.hidden = false;

  updateNotificationChannelFields();
}

export function resetNotificationRuleForm() {
  const form = document.getElementById("notification-rule-form");
  if (!form) return;

  form.reset();
  form.rule_id.value = "";
  form.is_enabled.checked = true;
  form.severity_min.value = "error";
  form.rate_limit_per_hour.value = "30";

  form.querySelectorAll("input[name='event_type']").forEach((input) => {
    input.checked = ["job.failed", "destination.failed", "provider.failed"].includes(input.value);
  });

  const submit = form.querySelector("button[type='submit']");
  if (submit) submit.textContent = t("settings.notifications.save_rule");
}

export function fillNotificationRuleForm(rule) {
  const form = document.getElementById("notification-rule-form");
  if (!form || !rule) return;

  form.rule_id.value = rule.id || "";
  form.name.value = rule.name || "";
  form.config_id.value = rule.config_id || "";
  form.is_enabled.checked = Boolean(rule.is_enabled);
  form.severity_min.value = rule.severity_min || "error";
  form.rate_limit_per_hour.value = rule.rate_limit_per_hour ?? 30;

  const eventTypes = Array.isArray(rule.event_types) ? rule.event_types : [];

  form.querySelectorAll("input[name='event_type']").forEach((input) => {
    input.checked = eventTypes.includes(input.value);
  });

  const submit = form.querySelector("button[type='submit']");
  if (submit) submit.textContent = t("settings.notifications.update_rule");

  const cancelBtn = form.querySelector("[data-settings-action='cancel-notification-rule-edit']");
  if (cancelBtn) cancelBtn.hidden = false;
}

/* Compat temporaire avec vieux app.js si import oublié */
export const updateNotificationFields = updateNotificationChannelFields;
export const resetNotificationForm = resetNotificationChannelForm;
export const fillNotificationConfigForm = fillNotificationChannelForm;
