from functools import wraps
import secrets
import uuid
from backend.utils.time import utc_now_iso

from flask import Blueprint, current_app, jsonify, request

from backend.models.api_token import ApiToken
from backend.models.user import User


dev_v2_bp = Blueprint("dev_v2", __name__, url_prefix="/api/v2/dev")


now = utc_now_iso


def require_dev_routes_enabled(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        settings = current_app.config["SETTINGS"]

        if not settings.DEBUG or not getattr(settings, "V2_DEV_ROUTES_ENABLED", False):
            return jsonify({"error": "Dev routes disabled"}), 404

        return fn(*args, **kwargs)

    return wrapper


@dev_v2_bp.post("/users")
@require_dev_routes_enabled
def create_user_dev():
    repo = current_app.config["USER_REPO_V2"]
    data = request.get_json(silent=True) or {}

    if not data.get("email"):
        return jsonify({"error": "email is required"}), 400

    user = User(
        id=str(uuid.uuid4()),
        email=data["email"],
        display_name=data.get("display_name"),
        role="user",
        is_active=True,
        created_at=now(),
        updated_at=now(),
    )

    repo.create(user)

    return jsonify({"id": user.id})


@dev_v2_bp.get("/users")
@require_dev_routes_enabled
def list_users_dev():
    repo = current_app.config["USER_REPO_V2"]

    if hasattr(repo, "list_all"):
        users = repo.list_all()
    elif hasattr(repo, "list_users"):
        users = repo.list_users()
    else:
        return jsonify({"error": "User repository listing unsupported"}), 500

    return jsonify([
        {
            "id": user.id,
            "email": user.email,
        }
        for user in users
    ])


@dev_v2_bp.post("/users/<user_id>/tokens")
@require_dev_routes_enabled
def create_user_token_dev(user_id):
    token_repo = current_app.config["API_TOKEN_REPO_V2"]

    data = request.get_json(silent=True) or {}

    raw_token = "dev_" + secrets.token_urlsafe(32)

    token = ApiToken(
        id=str(uuid.uuid4()),
        user_id=user_id,
        token=raw_token,
        label=data.get("label", "dev token"),
        is_active=True,
        created_at=now(),
        updated_at=now(),
    )

    token_repo.create(token)

    return jsonify({
        "token": raw_token,
        "user_id": user_id,
    }), 201


def serialize_token(token: ApiToken):
    return {
        "id": token.id,
        "user_id": token.user_id,
        "label": token.label,
        "is_active": token.is_active,
        "created_at": token.created_at,
        "updated_at": token.updated_at,
    }


@dev_v2_bp.get("/users/<user_id>/tokens")
@require_dev_routes_enabled
def list_user_tokens_dev(user_id):
    token_repo = current_app.config["API_TOKEN_REPO_V2"]

    tokens = token_repo.list_for_user(user_id)
    return jsonify([serialize_token(t) for t in tokens])


@dev_v2_bp.delete("/users/<user_id>/tokens/<token_id>")
@require_dev_routes_enabled
def deactivate_user_token_dev(user_id, token_id):
    token_repo = current_app.config["API_TOKEN_REPO_V2"]

    token_repo.deactivate(user_id, token_id)
    return "", 204