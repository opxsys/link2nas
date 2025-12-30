from __future__ import annotations

import secrets
from functools import wraps

from flask import Response, abort, request
from . import config


def _unauthorized():
    return Response(
        "Auth required",
        401,
        {"WWW-Authenticate": f'Basic realm="{config.ADMIN_REALM}", charset="UTF-8"'},
    )


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return ("", 204)

        if not config.ADMIN_ENABLED:
            abort(404)

        if not config.ADMIN_PASS:
            return _unauthorized()

        auth = request.authorization
        if not auth:
            return _unauthorized()

        ok_user = secrets.compare_digest(auth.username or "", config.ADMIN_USER)
        ok_pass = secrets.compare_digest(auth.password or "", config.ADMIN_PASS)
        if not (ok_user and ok_pass):
            return _unauthorized()

        return f(*args, **kwargs)
    return wrapper
