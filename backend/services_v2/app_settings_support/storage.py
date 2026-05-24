import copy
import json

from backend.models.app_setting import AppSetting


def get_json_setting(repository, key: str, default: dict) -> dict:
    setting = repository.get(key)
    if setting is None:
        return copy.deepcopy(default)

    try:
        value = json.loads(setting.value_json or "{}")
    except json.JSONDecodeError:
        return copy.deepcopy(default)

    if not isinstance(value, dict):
        return copy.deepcopy(default)

    return merge_with_default(default, value)


def save_json_setting(repository, key: str, value: dict, now_func) -> None:
    repository.upsert(
        AppSetting(
            key=key,
            value_json=json.dumps(value, ensure_ascii=False, sort_keys=True),
            updated_at=now_func(),
        )
    )


def merge_with_default(default: dict, value: dict) -> dict:
    merged = copy.deepcopy(default)

    if isinstance(value, dict):
        for key in default.keys():
            if key in value:
                merged[key] = value[key]

    return merged


def get_string_setting(repository, key: str) -> str | None:
    setting = repository.get(key)
    if setting is None:
        return None

    try:
        value = json.loads(setting.value_json or "null")
    except json.JSONDecodeError:
        return None

    return str(value) if isinstance(value, str) else None


def save_string_setting(repository, key: str, value: str, now_func) -> None:
    repository.upsert(
        AppSetting(
            key=key,
            value_json=json.dumps(value, ensure_ascii=False),
            updated_at=now_func(),
        )
    )
