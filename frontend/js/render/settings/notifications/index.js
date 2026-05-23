import { t } from "../../../i18n/index.js";
export { renderNotificationsHtml } from "./panel.js";

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
