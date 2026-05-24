import requests


def gotify_priority_for_severity(severity: str) -> int:
    value = str(severity or "").strip().lower()

    if value == "critical":
        return 10

    if value == "error":
        return 8

    if value == "warning":
        return 5

    return 2


def send_gotify(cfg: dict, event) -> None:
    server_url = str(cfg.get("server_url") or "").strip().rstrip("/")
    token = str(cfg.get("token") or "").strip()

    if not server_url:
        raise ValueError("Gotify server_url is required")

    if not token:
        raise ValueError("Gotify token is required")

    title = str(getattr(event, "title", "") or "Link2NAS notification").strip()
    message = str(getattr(event, "message", "") or "").strip()
    severity = str(getattr(event, "severity", "") or "info").strip().lower()
    event_type = str(getattr(event, "type", "") or "").strip()

    priority = gotify_priority_for_severity(severity)

    full_message = message

    if event_type:
        full_message = f"{message}\n\nType: {event_type}".strip()

    job_id = getattr(event, "job_id", None)
    if job_id:
        full_message = f"{full_message}\nJob: {job_id}".strip()

    url = f"{server_url}/message"

    response = requests.post(
        url,
        params={"token": token},
        json={
            "title": title,
            "message": full_message,
            "priority": priority,
        },
        timeout=8,
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"Gotify HTTP {response.status_code}: {response.text[:300]}"
        )
