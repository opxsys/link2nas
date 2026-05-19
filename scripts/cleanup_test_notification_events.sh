#!/usr/bin/env bash
set -euo pipefail

echo "=== Link2NAS V2 cleanup test notification events ==="
echo "Backend=${V2_DATABASE_BACKEND:-sqlite}"

python3 - <<'PY'
from datetime import UTC, datetime

from app import app


TEST_TITLES = {
    "System scope matching test",
    "System dispatcher processing test",
    "System dispatcher send test",
    "System rule matching test",
    "Dispatcher loop test",
    "Dedup test event",
    "Runtime max attempts test",
}

TEST_TYPES_PREFIX = (
    "test.",
)

TEST_PAYLOAD_MARKERS = {
    "admin_test",
    "test.system_",
    "test.system_scope.",
    "test.system_dispatcher.",
    "system-dispatcher-send-test-",
}


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def get_notification_event_repository():
    # Cas idéal si un jour on expose directement le repo
    for key in (
        "NOTIFICATION_EVENT_REPOSITORY_V2",
        "NOTIFICATION_EVENT_REPO_V2",
    ):
        repo = app.config.get(key)
        if repo:
            return repo

    # Cas actuel probable : via service notification
    service = app.config.get("NOTIFICATION_SERVICE_V2")
    if service and hasattr(service, "notification_event_repository"):
        return service.notification_event_repository

    # Cas via factory/repositories stockés
    repos = app.config.get("REPOSITORIES_V2") or app.config.get("REPOS_V2")
    if repos and hasattr(repos, "notification_event_repository"):
        return repos.notification_event_repository

    available = sorted(
        key for key in app.config.keys()
        if "NOTIFICATION" in key or "REPO" in key
    )

    raise RuntimeError(
        "Notification event repository not found. Available related keys: "
        + ", ".join(available)
    )


def is_test_event(event) -> bool:
    title = str(getattr(event, "title", "") or "").strip()
    event_type = str(getattr(event, "type", "") or "").strip()
    payload_json = str(getattr(event, "payload_json", "") or "")

    if title in TEST_TITLES:
        return True

    if event_type.startswith(TEST_TYPES_PREFIX):
        return True

    for marker in TEST_PAYLOAD_MARKERS:
        if marker in payload_json:
            return True

    return False


with app.app_context():
    repo = get_notification_event_repository()

    if not hasattr(repo, "list_all"):
        raise RuntimeError("Notification event repository does not support list_all")

    if not hasattr(repo, "mark_failed"):
        methods = [name for name in dir(repo) if not name.startswith("_")]
        raise RuntimeError(
            "Notification event repository has no mark_failed method. Methods: "
            + ", ".join(methods)
        )

    events = repo.list_all(limit=500, status=None)

    candidates = []
    for event in events:
        status = str(getattr(event, "status", "") or "").strip().lower()

        if status not in {"pending", "retrying"}:
            continue

        if not is_test_event(event):
            continue

        candidates.append(event)

    print(f"candidates={len(candidates)}")

    changed = 0
    timestamp = now_iso()

    for event in candidates:
        try:
            repo.mark_failed(
                event.id,
                "Marked failed by cleanup_test_notification_events.sh",
                timestamp,
            )
        except TypeError:
            repo.mark_failed(
                event.id,
                "Marked failed by cleanup_test_notification_events.sh",
            )

        changed += 1
        print(f"marked_failed id={event.id} type={event.type} title={event.title!r}")

    print(f"changed={changed}")
PY

echo "=== OK: test notification events cleanup done ==="
