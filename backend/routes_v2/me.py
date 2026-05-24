from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from backend.routes_v2._context import get_user_context
from backend.routes_v2.admin_users import now
from backend.routes_v2.admin_users_support.validation import (
    parse_optional_datetime as _parse_optional_datetime,
    validate_email as _validate_email,
    validate_password as _validate_password,
)
from backend.routes_v2.me_support.serialization import serialize_me, serialize_integration_settings
from backend.routes_v2.me_support.space import _get_or_create_public_slug, _user_space_path
from backend.services_v2.rate_limit_service import rate_limit_response
from backend.utils.email_templates import build_email_verification_email
from backend.utils.user_language import validate_preferred_language


me_v2_bp = Blueprint("me_v2", __name__, url_prefix="/api/v2")

@me_v2_bp.get("/me")
def get_me_v2():
    ctx = get_user_context()
    user_repo = current_app.config["USER_REPO_V2"]

    user = user_repo.get_by_id(ctx.user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify(serialize_me(user))


@me_v2_bp.patch("/me")
def update_me_v2():
    ctx = get_user_context()
    user_repo = current_app.config["USER_REPO_V2"]

    user = user_repo.get_by_id(ctx.user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json(silent=True) or {}

    try:
        if "display_name" in data:
            user.display_name = str(data.get("display_name") or "").strip() or None

        if "email" in data:
            email = str(data.get("email") or "").strip().lower()
            _validate_email(email)

            existing = user_repo.get_by_email(email)
            if existing and existing.id != user.id:
                return jsonify({"error": "A user with this email already exists"}), 409

            if email != user.email:
                settings = current_app.config.get("SETTINGS")
                single_user_mode = bool(
                    getattr(settings, "LINK2NAS_SINGLE_USER_MODE", False)
                )

                user.email = email

                if single_user_mode:
                    user.email_verified_at = now()
                    user.email_verification_token = None
                else:
                    user.email_verified_at = None
                    user.email_verification_token = None

        if "preferred_language" in data:
            user.preferred_language = validate_preferred_language(data.get("preferred_language"))

        if "ui_theme" in data:
            _valid_themes = frozenset({"auto", "light", "night", "high_contrast", "colorblind"})
            val = str(data.get("ui_theme") or "auto").strip()
            user.ui_theme = val if val in _valid_themes else "auto"

        if "receive_application_emails" in data:
            user.receive_application_emails = bool(data["receive_application_emails"])

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    user.updated_at = now()
    user_repo.update(user)

    return jsonify(serialize_me(user))


@me_v2_bp.post("/me/password")
def change_my_password_v2():

    settings = current_app.config.get("SETTINGS")
    if bool(getattr(settings, "LINK2NAS_SINGLE_USER_MODE", False)):
        return jsonify({
            "error": "Password change is disabled in single-user mode"
        }), 403

    limited = rate_limit_response(
        "me_password_change",
        "authenticated",
        limit_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_MAX",
        window_attr="V2_RATE_LIMIT_PUBLIC_TOKEN_CONFIRM_WINDOW_SECONDS",
    )
    if limited:
        return limited

    ctx = get_user_context()
    user_repo = current_app.config["USER_REPO_V2"]

    user = user_repo.get_by_id(ctx.user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json(silent=True) or {}

    current_password = str(data.get("current_password") or "")
    new_password = str(data.get("new_password") or "")

    if not user.password_hash or not check_password_hash(user.password_hash, current_password):
        return jsonify({"error": "Current password is invalid"}), 400

    try:
        _validate_password(new_password, required=True)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    user.password_hash = generate_password_hash(new_password)
    user.force_password_change = False
    user.password_reset_token = None
    user.password_reset_sent_at = None
    user.updated_at = now()
    user_repo.update(user)

    return jsonify({"ok": True})


@me_v2_bp.get("/me/integration-settings")
def get_my_integration_settings_v2():
    ctx = get_user_context()
    service = current_app.config["USER_INTEGRATION_SETTINGS_SERVICE_V2"]

    settings = service.get_for_user(ctx.user_id)

    return jsonify(serialize_integration_settings(settings))


@me_v2_bp.put("/me/integration-settings")
def update_my_integration_settings_v2():
    ctx = get_user_context()
    service = current_app.config["USER_INTEGRATION_SETTINGS_SERVICE_V2"]

    data = request.get_json(silent=True) or {}

    if data.get("prowlarr_enabled"):
        api_key_service = current_app.config["USER_API_KEY_SERVICE_V2"]
        user_api_keys = api_key_service.list_for_user(ctx.user_id)
        has_qbt_key = any(
            k.get("is_active") and "qbittorrent:write" in k.get("scopes", [])
            for k in user_api_keys
        )
        if not has_qbt_key:
            return jsonify({
                "error": "An active API key with qbittorrent:write scope is required to enable Prowlarr integration."
            }), 400

    try:
        settings = service.update_for_user(ctx.user_id, data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(serialize_integration_settings(settings))

@me_v2_bp.post("/me/request-email-verification")
def request_email_verification_v2():
    limited = rate_limit_response(
        "email_verification_request",
        "authenticated",
        limit_attr="V2_RATE_LIMIT_EMAIL_REQUEST_MAX",
        window_attr="V2_RATE_LIMIT_EMAIL_REQUEST_WINDOW_SECONDS",
    )
    if limited:
        return limited

    ctx = get_user_context()
    user_repo = current_app.config["USER_REPO_V2"]
    token_service = current_app.config["ACCOUNT_TOKEN_SERVICE_V2"]
    smtp_service = current_app.config.get("SMTP_SERVICE_V2")
    app_settings = current_app.config["APP_SETTINGS_SERVICE_V2"]

    user = user_repo.get_by_id(ctx.user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.email_verified_at:
        return jsonify({"ok": True, "message": "Email already verified"})

    if not smtp_service or not smtp_service.is_email_sending_available():
        return jsonify({"error": "Email sending is not configured."}), 503

    token, raw_token = token_service.create_token(
        user_id=user.id,
        token_type="email_verification",
        created_by_user_id=user.id,
        ttl_hours=app_settings.get_email_verification_ttl_hours(),
    )

    verification_url = token_service.build_email_verification_url(raw_token)

    app_name = app_settings.get_effective_app_name(
        env_fallback=getattr(current_app.config.get("SETTINGS"), "APP_NAME", "")
    )

    try:
        email_svc = current_app.config.get("EMAIL_TEMPLATE_SERVICE_V2")
        if email_svc:
            subject, body = email_svc.render(
                "email_verification", user.preferred_language,
                app_name=app_name, url=verification_url, expires_at=token.expires_at,
            )
        else:
            subject, body = build_email_verification_email(
                user.preferred_language, verification_url, token.expires_at, app_name=app_name
            )
        smtp_service.send_email(to_email=user.email, subject=subject, body=body)
    except Exception as exc:
        return jsonify({
            "ok": False,
            "error": f"Email verification failed: {exc}",
        }), 502

    user.email_verification_token = None
    user.updated_at = now()
    user_repo.update(user)

    return jsonify({
        "ok": True,
        "message": f"Email verification sent to {user.email}",
        "expires_at": token.expires_at,
        "verification_url": verification_url,
    })



@me_v2_bp.get("/me/public-space")
def get_my_public_space():
    ctx = get_user_context()
    user_repo = current_app.config["USER_REPO_V2"]
    settings = current_app.config["SETTINGS"]

    user = user_repo.get_by_id(ctx.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.can_use_local_space:
        return jsonify({"error": "Local space is not allowed for this account"}), 403

    slug = _get_or_create_public_slug(user, user_repo)
    try:
        space_path = _user_space_path(user.id, settings)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    files = []
    total_size = 0
    if space_path.is_dir():
        for entry in sorted(space_path.rglob("*")):
            if entry.is_file():
                size = entry.stat().st_size
                total_size += size
                relative_path = entry.relative_to(space_path).as_posix()
                files.append({
                    "name": entry.name,
                    "relative_path": relative_path,
                    "size_bytes": size,
                })

    app_settings = current_app.config.get("APP_SETTINGS_SERVICE_V2")
    env_base_url = getattr(settings, "PUBLIC_BASE_URL", "") or ""
    base_url = ""
    if app_settings:
        try:
            base_url = app_settings.get_effective_public_base_url(env_base_url) or ""
        except Exception:
            base_url = env_base_url
    if not base_url:
        base_url = env_base_url

    public_url = f"{base_url.rstrip('/')}/u/{slug}/"

    return jsonify({
        "slug": slug,
        "url": public_url,
        "file_count": len(files),
        "total_size_bytes": total_size,
        "files": files,
    })


@me_v2_bp.post("/me/public-space/cleanup")
def cleanup_my_public_space():
    ctx = get_user_context()
    user_repo = current_app.config["USER_REPO_V2"]
    settings = current_app.config["SETTINGS"]

    user = user_repo.get_by_id(ctx.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.can_use_local_space:
        return jsonify({"error": "Local space is not allowed for this account"}), 403

    try:
        space_path = _user_space_path(user.id, settings)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    deleted_files = []
    deleted_bytes = 0

    if space_path.is_dir():
        # Collect all file info before any deletion to avoid iterator invalidation
        to_delete = []
        for entry in space_path.rglob("*"):
            if entry.is_file():
                try:
                    to_delete.append((entry, entry.stat().st_size))
                except OSError:
                    pass

        for entry, size in to_delete:
            try:
                entry.unlink()
                deleted_files.append(entry.relative_to(space_path).as_posix())
                deleted_bytes += size
            except OSError:
                pass

        # Remove empty subdirectories bottom-up, never space_path itself
        for dirpath in sorted(space_path.rglob("*"), reverse=True):
            if dirpath.is_dir() and dirpath != space_path:
                try:
                    dirpath.rmdir()
                except OSError:
                    pass

    return jsonify({
        "ok": True,
        "deleted_files": deleted_files,
        "deleted_count": len(deleted_files),
        "deleted_bytes": deleted_bytes,
    })
