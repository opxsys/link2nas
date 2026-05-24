from __future__ import annotations


def run_once_for_user(
    user_id: str,
    limit: int,
    notification_event_repository,
    dispatch_func,
    mark_failure_func,
    now_func,
    on_state_update=None,
) -> dict:
    started_at = now_func()

    result = {
        "started_at": started_at,
        "finished_at": None,
        "user_id": user_id,
        "limit": limit,
        "processed": 0,
        "sent": 0,
        "retrying": 0,
        "failed": 0,
        "skipped": 0,
        "errors": [],
    }

    try:
        events = notification_event_repository.list_for_user(
            user_id=user_id,
            limit=limit,
        )

        candidates = [
            event
            for event in events
            if str(getattr(event, "status", "") or "").lower() in {"pending", "retrying"}
        ]

        for event in candidates[:limit]:
            result["processed"] += 1

            try:
                outcome = dispatch_func(user_id, event)

                if outcome == "sent":
                    result["sent"] += 1
                elif outcome == "skipped":
                    result["skipped"] += 1
                else:
                    result["skipped"] += 1

            except Exception as exc:
                mark_failure_func(event, exc)

                refreshed = notification_event_repository.get_by_id(user_id, event.id)
                status = str(getattr(refreshed, "status", "") or "").lower()

                if status == "failed":
                    result["failed"] += 1
                else:
                    result["retrying"] += 1

                result["errors"].append({
                    "event_id": event.id,
                    "error": str(exc),
                })

        result["finished_at"] = now_func()
        last_error = None if not result["errors"] else result["errors"][-1]["error"]

        if on_state_update:
            on_state_update(result["finished_at"], last_error, result)

        return result

    except Exception as exc:
        result["finished_at"] = now_func()
        result["errors"].append({"error": str(exc)})

        if on_state_update:
            on_state_update(result["finished_at"], str(exc), result)

        raise


def run_once_all_users(
    limit: int,
    user_repository,
    run_for_user_func,
    now_func,
    on_state_update=None,
) -> dict:
    started_at = now_func()

    result = {
        "started_at": started_at,
        "finished_at": None,
        "limit": limit,
        "users_processed": 0,
        "processed": 0,
        "sent": 0,
        "retrying": 0,
        "failed": 0,
        "skipped": 0,
        "errors": [],
        "per_user": [],
    }

    try:
        if not user_repository:
            raise RuntimeError("User repository is not configured")

        if hasattr(user_repository, "list_all"):
            users = user_repository.list_all()
        elif hasattr(user_repository, "list_users"):
            users = user_repository.list_users()
        elif hasattr(user_repository, "list"):
            users = user_repository.list()
        else:
            raise RuntimeError("User repository has no list method")

        for user in users:
            user_id = str(getattr(user, "id", "") or "").strip()
            is_active = bool(getattr(user, "is_active", False))

            if not user_id or not is_active:
                continue

            user_result = run_for_user_func(user_id=user_id, limit=limit)

            result["users_processed"] += 1
            result["processed"] += int(user_result.get("processed") or 0)
            result["sent"] += int(user_result.get("sent") or 0)
            result["retrying"] += int(user_result.get("retrying") or 0)
            result["failed"] += int(user_result.get("failed") or 0)
            result["skipped"] += int(user_result.get("skipped") or 0)

            if user_result.get("errors"):
                result["errors"].extend(user_result["errors"])

            result["per_user"].append(user_result)

        result["finished_at"] = now_func()
        last_error = None if not result["errors"] else str(result["errors"][-1].get("error"))

        if on_state_update:
            on_state_update(result["finished_at"], last_error, result)

        return result

    except Exception as exc:
        result["finished_at"] = now_func()
        result["errors"].append({"error": str(exc)})

        if on_state_update:
            on_state_update(result["finished_at"], str(exc), result)

        raise
