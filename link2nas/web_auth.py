# link2nas/web_auth.py
from __future__ import annotations

import secrets
from functools import wraps
from typing import Callable, TypeVar, Any

from flask import Response, abort, request

from .config import Settings

F = TypeVar("F", bound=Callable[..., Any])


def _unauthorized(realm: str) -> Response:
    """
    HTTP 401 response for Basic Auth.
    """
    return Response(
        "Auth required",
        401,
        {"WWW-Authenticate": f'Basic realm="{realm}", charset="UTF-8"'},
    )


def make_require_admin(s: Settings):
    """
    Build a @require_admin decorator bound to Settings.

    Rules:
    - admin disabled => 404 (hide admin surface)
    - missing config => 401 (fail closed)
    - constant-time comparisons
    """

    def require_admin(f: F) -> F:
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.method == "OPTIONS":
                return ("", 204)

            if not s.admin_enabled:
                abort(404)

            if not (s.admin_user and s.admin_pass):
                return _unauthorized(s.admin_realm)

            auth = request.authorization
            if not auth:
                return _unauthorized(s.admin_realm)

            ok_user = secrets.compare_digest(auth.username or "", s.admin_user)
            ok_pass = secrets.compare_digest(auth.password or "", s.admin_pass)
            if not (ok_user and ok_pass):
                return _unauthorized(s.admin_realm)

            return f(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return require_admin
