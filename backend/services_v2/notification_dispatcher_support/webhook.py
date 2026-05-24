import json
import requests


def build_webhook_payload(config, event) -> dict:
    raw_payload = getattr(event, "payload", None)

    if isinstance(raw_payload, dict):
        event_payload = raw_payload
    else:
        raw_payload_json = getattr(event, "payload_json", None) or "{}"

        try:
            decoded = json.loads(raw_payload_json)
        except Exception:
            decoded = {}

        event_payload = decoded if isinstance(decoded, dict) else {}

    return {
        "app": "link2nas",
        "config_id": getattr(config, "id", None),
        "config_name": getattr(config, "name", None),
        "event_id": getattr(event, "id", None),
        "user_id": getattr(event, "user_id", None),
        "job_id": getattr(event, "job_id", None),
        "type": getattr(event, "type", None),
        "severity": getattr(event, "severity", None),
        "title": getattr(event, "title", None),
        "message": getattr(event, "message", None),
        "status": getattr(event, "status", None),
        "attempts": getattr(event, "attempts", None),
        "created_at": getattr(event, "created_at", None),
        "updated_at": getattr(event, "updated_at", None),
        "payload": event_payload,
    }


def send_webhook(cfg: dict, config, event) -> None:
    url = str(cfg.get("url") or "").strip()
    method = str(cfg.get("method") or "POST").strip().upper()
    headers = cfg.get("headers") or {}

    if not url:
        raise ValueError("Webhook url is required")

    if method not in {"POST", "PUT"}:
        raise ValueError("Webhook method must be POST or PUT")

    if not isinstance(headers, dict):
        raise ValueError("Webhook headers must be an object")

    payload = build_webhook_payload(config, event)

    response = requests.request(
        method,
        url,
        headers=headers,
        json=payload,
        timeout=8,
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"Webhook HTTP {response.status_code}: {response.text[:300]}"
        )
