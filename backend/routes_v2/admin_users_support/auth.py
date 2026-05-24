from flask import current_app, jsonify
from backend.routes_v2._context import get_user_context


def require_super_admin():
    ctx = get_user_context()

    if ctx.role != "super_admin":
        return None, (jsonify({"error": "Forbidden"}), 403)

    return ctx, None


def require_admin_user_management():
    ctx, err = require_super_admin()
    if err:
        return ctx, err

    settings = current_app.config.get("SETTINGS")
    if bool(getattr(settings, "LINK2NAS_SINGLE_USER_MODE", False)):
        return None, (
            jsonify({"error": "User management is disabled in single-user mode"}),
            403,
        )

    return ctx, None
