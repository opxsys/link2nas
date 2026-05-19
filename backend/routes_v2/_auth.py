from functools import wraps
from flask import jsonify

from backend.routes_v2._context import get_user_context


def require_role(*allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ctx = get_user_context()

            if ctx.role not in allowed_roles:
                return jsonify({"error": "Forbidden"}), 403

            return fn(*args, **kwargs)

        return wrapper
    return decorator
