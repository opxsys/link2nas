import json

from flask import current_app

from backend.routes_v2._context import get_user_context
from backend.routes_v2.jobs_support.helpers import _parse_json_object, _filename_from_path
from backend.routes_v2.jobs_support.display_path import local_display_path
from backend.services_v2.destination_registry import DESTINATION_ALIAS_KEYS, DESTINATION_KEYS


def _parse_output_links(job) -> list[dict]:
    try:
        if not job.output_links_json:
            return []

        parsed = json.loads(job.output_links_json)

        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]

        return []
    except Exception:
        return []


def _parse_provider_payload(job) -> dict:
    try:
        if not job.provider_payload_json:
            return {}

        parsed = json.loads(job.provider_payload_json)

        if isinstance(parsed, dict):
            return parsed

        return {}
    except Exception:
        return {}


def _active_provider_configs(ctx) -> list[dict]:
    factory = current_app.config.get("USER_PROVIDER_FACTORY_V2")
    if not factory:
        return []

    try:
        configs = factory.list_enabled_provider_configs_for_user(ctx.user_id)
    except Exception:
        return []

    return [
        {
            "id": config.id,
            "name": config.name,
            "provider_type": config.provider_type,
            "provider_name": config.provider_type,
            "is_default": config.is_default,
        }
        for config in configs
    ]


def _active_provider_names(ctx) -> list[str]:
    names = []

    for config in _active_provider_configs(ctx):
        provider_name = config.get("provider_type") or config.get("provider_name")
        if provider_name and provider_name not in names:
            names.append(provider_name)

    return names


def _active_real_destination_configs(ctx) -> list[dict]:
    factory = current_app.config.get("USER_DESTINATION_FACTORY_V2")
    if factory:
        try:
            configs = factory.list_enabled_destination_configs_for_user(ctx.user_id)
        except Exception:
            configs = []
    else:
        service = current_app.config.get("DESTINATION_CONFIG_SERVICE_V2")
        if not service:
            return []

        try:
            configs = service.list_destination_configs(ctx)
        except Exception:
            return []

        configs = [config for config in configs if config.is_enabled]

    result = []

    for config in configs:
        destination_type = DESTINATION_ALIAS_KEYS.get(config.destination_type, config.destination_type)

        if destination_type not in DESTINATION_KEYS:
            continue

        result.append({
            "id": config.id,
            "name": config.name,
            "destination_type": destination_type,
            "destination_name": destination_type,
            "is_default": config.is_default,
        })

    return result


def _active_real_destination_names(ctx) -> list[str]:
    names = []

    for config in _active_real_destination_configs(ctx):
        destination_name = config.get("destination_type") or config.get("destination_name")
        if destination_name and destination_name not in names:
            names.append(destination_name)

    return names


def serialize_job(job):
    ctx = get_user_context()
    service = current_app.config.get("JOB_SERVICE_V2")
    allowed_actions = service.get_allowed_actions(job) if service else []

    output_links = _parse_output_links(job)
    provider_payload = _parse_provider_payload(job)

    first_link = output_links[0] if output_links else {}

    provider_files = provider_payload.get("files") or []
    if not isinstance(provider_files, list):
        provider_files = []

    links_by_file_id = {}
    links_by_index = {}

    for index, link in enumerate(output_links, start=1):
        if not isinstance(link, dict):
            continue

        file_id = link.get("file_id") or index
        links_by_file_id[str(file_id)] = link
        links_by_index[index] = link

    serialized_files = []

    if provider_files:
        for index, item in enumerate(provider_files, start=1):
            if not isinstance(item, dict):
                continue

            file_id = item.get("id") or index
            link = links_by_file_id.get(str(file_id)) or links_by_index.get(index) or {}

            path = (
                item.get("path")
                or item.get("filename")
                or item.get("name")
                or link.get("relative_path")
                or link.get("path")
                or link.get("filename")
            )

            filename = (
                item.get("filename")
                or item.get("name")
                or link.get("filename")
                or _filename_from_path(path)
            )

            serialized_files.append({
                "id": file_id,
                "path": path,
                "filename": filename,
                "bytes": item.get("bytes") or item.get("filesize") or item.get("size") or link.get("filesize"),
                "filesize": item.get("filesize") or item.get("bytes") or item.get("size") or link.get("filesize"),
                "debrid_link": link.get("debrid_link") or item.get("link") or item.get("debrid_link"),
                "download_url": link.get("url") or item.get("download_url"),
            })

    elif output_links:
        for index, item in enumerate(output_links, start=1):
            path = item.get("relative_path") or item.get("path") or item.get("filename") or f"file_{index}"
            serialized_files.append({
                "id": item.get("file_id") or index,
                "path": path,
                "filename": item.get("filename") or _filename_from_path(path),
                "bytes": item.get("filesize"),
                "filesize": item.get("filesize"),
                "debrid_link": item.get("debrid_link"),
                "download_url": item.get("url"),
            })

    filename = (
        provider_payload.get("filename")
        or provider_payload.get("name")
        or first_link.get("filename")
        or None
    )

    filesize = (
        provider_payload.get("bytes")
        or provider_payload.get("filesize")
        or provider_payload.get("size")
        or first_link.get("filesize")
        or None
    )

    progress = provider_payload.get("progress")
    if progress is None:
        progress = 100 if job.status in {"downloaded", "ready", "completed"} else 0

    is_per_file = job.output_mode == "per_file" or len(output_links) > 1

    download_url = None if is_per_file else first_link.get("url")
    debrid_link = None

    provider_links = provider_payload.get("links")
    if not is_per_file and isinstance(provider_links, list) and provider_links:
        debrid_link = provider_links[0]

    destination_type = job.destination_name

    active_provider_configs = _active_provider_configs(ctx)
    active_real_destination_configs = _active_real_destination_configs(ctx)

    active_provider_names = _active_provider_names(ctx)
    active_real_destination_names = _active_real_destination_names(ctx)

    active_provider_config_ids = {
        str(config.get("id"))
        for config in active_provider_configs
        if config.get("id")
    }

    active_destination_config_ids = {
        str(config.get("id"))
        for config in active_real_destination_configs
        if config.get("id")
    }

    provider_available = (
        (job.provider_config_id and str(job.provider_config_id) in active_provider_config_ids)
        or job.provider_name in active_provider_names
    )

    destination_available = (
        not job.destination_config_id
        or str(job.destination_config_id) in active_destination_config_ids
        or not job.destination_name
        or job.destination_name in active_real_destination_names
    )

    settings = current_app.config.get("SETTINGS")
    userdata_dir = str(getattr(settings, "USERDATA_DIR", "") or "") if settings else ""
    destination_display_path = local_display_path(
        destination_path=job.destination_path,
        destination_name=job.destination_name,
        destination_type=destination_type,
        user_id=ctx.user_id,
        userdata_dir=userdata_dir,
    )

    return {
        "id": job.id,
        "source_type": job.source_type,
        "source_value": job.source_value,
        "status": job.status,
        "allowed_actions": allowed_actions,

        "provider_config_id": job.provider_config_id,
        "provider_name": job.provider_name,
        "provider_type": job.provider_name,
        "provider_profile_name": job.provider_profile_name,
        "provider_resource_id": job.provider_resource_id,
        "provider_status": job.provider_status,
        "provider_payload_json": job.provider_payload_json,
        "provider_available": provider_available,
        "destination_available": destination_available,

        "destination_config_id": job.destination_config_id,
        "destination_name": job.destination_name,
        "destination_type": destination_type,
        "destination_profile_name": job.destination_profile_name,

        "output_mode": "per_file" if is_per_file else job.output_mode,
        "output_links_json": job.output_links_json,
        "output_links": output_links,
        "unrestricted_at": job.unrestricted_at,

        "error_message": job.error_message,

        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "cancelled_at": job.cancelled_at,

        "torrent_id": job.provider_resource_id,
        "torrent_status": job.provider_status,
        "selected_files": None,

        "filename": filename,
        "filesize": filesize,
        "progress": progress,
        "download_url": download_url,
        "debrid_link": debrid_link,
        "download_id": first_link.get("provider_download_id"),

        "files": serialized_files,

        "send_to_destination": bool(job.send_to_destination),
        "sent_to_destination": bool(job.sent_to_destination),
        "destination_status": job.destination_status,
        "destination_message": job.destination_message,
        "destination_message_key": job.destination_message_key,
        "destination_message_params": _parse_json_object(job.destination_message_params),
        "destination_last_attempt": job.destination_last_attempt,
        "sent_to_destination_at": job.sent_to_destination_at,
        "destination_path": job.destination_path,
        "destination_display_path": destination_display_path,
        "destination_progress": int(job.destination_progress or 0),

        "active_provider_names": active_provider_names,
        "active_provider_configs": active_provider_configs,
        "active_real_destination_names": active_real_destination_names,
        "active_real_destination_configs": active_real_destination_configs,
        "can_clone_with_other_provider": len([
            p for p in active_provider_configs
            if p.get("id") != job.provider_config_id
        ]) >= 1,
        "can_send_to_other_destination": len(active_real_destination_configs) >= 1,

        "last_message": job.error_message,
        "last_message_key": None,
        "last_message_params": None,
    }
