export function buildDestinationConfigJsonFromState(dest) {
  const cfg = dest.config || {};
  const type = dest.destination_type || dest.destination_name;

  if (type === "synology") {
    return JSON.stringify({
      synology_url: cfg.synology_url || "",
      username: cfg.username || "",
      destination_base: cfg.destination_base || "",
      verify_ssl: cfg.verify_ssl ?? true,
    });
  }

  return JSON.stringify({
    base_path: cfg.base_path || "downloads",
  });
}

export function buildDestinationConfig(form) {
  const destinationType = form.destination_type?.value || form.destination_name?.value;

  if (destinationType === "local") {
    return {
      base_path: form.base_path.value,
    };
  }

  return {
    synology_url: form.synology_url.value,
    username: form.username.value,
    password: form.password.value,
    verify_ssl: Boolean(form.verify_ssl.checked),
    destination_base: form.destination_base.value,
  };
}

export function buildNotificationChannelPayload(form) {
  const channel = String(form.channel?.value || "").trim().toLowerCase();

  const payload = {
    name: String(form.name?.value || "").trim(),
    channel,
    is_enabled: Boolean(form.is_enabled?.checked),
    is_default: Boolean(form.is_default?.checked),
    config: {},
  };

  if (channel === "email") {
    const toEmail = String(form.to_email?.value || "").trim();

    if (toEmail) {
      payload.config.to_email = toEmail;
    }

    return payload;
  }

  if (channel === "gotify") {
    payload.config.server_url = String(form.gotify_server_url?.value || "").trim();

    const token = String(form.gotify_token?.value || "").trim();
    if (token) {
      payload.config.token = token;
    }

    return payload;
  }

  if (channel === "webhook") {
    payload.config.url = String(form.webhook_url?.value || "").trim();
    payload.config.method = String(form.webhook_method?.value || "POST").trim().toUpperCase();

    const headersRaw = String(form.webhook_headers?.value || "").trim();

    if (headersRaw) {
      payload.config.headers = JSON.parse(headersRaw);
    }

    return payload;
  }

  return payload;
}

export function buildNotificationRulePayload(form) {
  const eventTypes = Array.from(form.querySelectorAll("input[name='event_type']:checked"))
    .map((input) => input.value)
    .filter(Boolean);

  return {
    name: String(form.name?.value || "").trim(),
    config_id: String(form.config_id?.value || "").trim(),
    is_enabled: Boolean(form.is_enabled?.checked),
    severity_min: String(form.severity_min?.value || "error").trim(),
    event_types: eventTypes,
    rate_limit_per_hour: Number(form.rate_limit_per_hour?.value || 30),
    scope: "user",
  };
}
