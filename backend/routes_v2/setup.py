import uuid
from backend.utils.time import utc_now_iso

from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash

from backend.models.user import User
from backend.routes_v2.admin_users_support.validation import (
    validate_email as _validate_email,
    validate_password as _validate_password,
)
from backend.utils.user_language import validate_preferred_language

setup_v2_bp = Blueprint("setup_v2", __name__, url_prefix="/api/v2/setup")


now = utc_now_iso


def _error(message: str, status_code: int = 400):
    return jsonify({"error": message}), status_code


@setup_v2_bp.get("/status")
def setup_status_v2():
    from flask import current_app

    user_repo = current_app.config["USER_REPO_V2"]
    return jsonify({
        "setup_required": user_repo.count_users() == 0,
    })


@setup_v2_bp.post("/first-admin")
def create_first_admin_v2():
    from flask import current_app

    user_repo = current_app.config["USER_REPO_V2"]

    if user_repo.count_users() > 0:
        return _error("Setup already completed", 409)

    data = request.get_json(silent=True) or {}

    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")
    display_name = str(data.get("display_name") or "").strip() or None
    preferred_language = validate_preferred_language(data.get("preferred_language"))

    try:
        _validate_email(email)
        _validate_password(password, required=True)
    except ValueError as exc:
        return _error(str(exc))

    timestamp = now()

    user = User(
        id=str(uuid.uuid4()),
        email=email,
        display_name=display_name,
        password_hash=generate_password_hash(password),
        role="super_admin",
        is_active=True,
        created_at=timestamp,
        updated_at=timestamp,
        preferred_language=preferred_language,
    )

    user_repo.create(user)

    return jsonify({
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
    }), 201
