from flask import current_app


def _app_settings_service():
    return current_app.config.get("APP_SETTINGS_SERVICE_V2")


def _get_magic_login_ttl_minutes() -> int:
    service = _app_settings_service()
    if not service:
        return 15
    return service.get_magic_login_ttl_minutes()
