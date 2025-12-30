from __future__ import annotations

from . import config


def payload() -> dict:
    return {
        "success": True,
        "version": config.APP_VERSION,
        "capabilities": {"nas_enabled": bool(config.NAS_ENABLED)},
    }
