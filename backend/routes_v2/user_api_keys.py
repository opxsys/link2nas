from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2._context import get_user_context
from backend.services_v2.user_api_key_service import UserApiKeyValidationError


user_api_keys_v2_bp = Blueprint(
    "user_api_keys_v2",
    __name__,
    url_prefix="/api/v2",
)


def _service():
    return current_app.config["USER_API_KEY_SERVICE_V2"]


@user_api_keys_v2_bp.get("/me/api-keys")
def list_my_api_keys_v2():
    ctx = get_user_context()
    return jsonify(_service().list_for_user(ctx.user_id))


@user_api_keys_v2_bp.post("/me/api-keys")
def create_my_api_key_v2():
    ctx = get_user_context()
    data = request.get_json(silent=True) or {}

    try:
        result = _service().create_for_user(
            user_id=ctx.user_id,
            name=data.get("name") or "",
            scopes=data.get("scopes") or [],
        )
    except UserApiKeyValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        message = str(exc)

        if "UNIQUE" in message or "duplicate" in message.lower():
            return jsonify({"error": "API key name or prefix already exists"}), 409

        raise

    return jsonify(result), 201


@user_api_keys_v2_bp.post("/me/api-keys/<key_id>/revoke")
def revoke_my_api_key_v2(key_id: str):
    ctx = get_user_context()

    try:
        result = _service().revoke_for_user(ctx.user_id, key_id)
    except UserApiKeyValidationError as exc:
        return jsonify({"error": str(exc)}), 404

    return jsonify(result)


@user_api_keys_v2_bp.delete("/me/api-keys/<key_id>")
def delete_my_api_key_v2(key_id: str):
    ctx = get_user_context()

    ok = _service().delete_for_user(ctx.user_id, key_id)

    if not ok:
        return jsonify({"error": "API key not found"}), 404

    return "", 204
