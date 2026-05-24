from backend.services_v2.notification_support.validation import NotificationValidationError


def serialize_config(
    decode_config_func,
    encode_config_func,
    channel: str,
    config_payload: "dict | None",
    existing_config,
) -> str:
    existing = {}

    if existing_config:
        existing = decode_config_func(existing_config.config_json)

    incoming = dict(config_payload or {})

    if channel == "email":
        config = {
            "to_email": str(incoming.get("to_email") or existing.get("to_email") or "").strip(),
        }
        return encode_config_func(config)

    if channel == "gotify":
        server_url = str(incoming.get("server_url") or existing.get("server_url") or "").strip().rstrip("/")
        token = str(incoming.get("token") or existing.get("token") or "").strip()

        if not server_url:
            raise NotificationValidationError("Gotify server_url is required")

        if not token:
            raise NotificationValidationError("Gotify token is required")

        return encode_config_func({
            "server_url": server_url,
            "token": token,
        })

    if channel == "webhook":
        url = str(incoming.get("url") or existing.get("url") or "").strip()
        method = str(incoming.get("method") or existing.get("method") or "POST").strip().upper()
        headers = incoming.get("headers", existing.get("headers", {}))

        if not url:
            raise NotificationValidationError("Webhook url is required")

        if method not in {"POST", "PUT"}:
            raise NotificationValidationError("Webhook method must be POST or PUT")

        if headers is None:
            headers = {}

        if not isinstance(headers, dict):
            raise NotificationValidationError("Webhook headers must be an object")

        return encode_config_func({
            "url": url,
            "method": method,
            "headers": headers,
        })

    raise NotificationValidationError("Unsupported notification channel")
