from flask import Blueprint, current_app, jsonify, request

from backend.routes_v2.admin_users import require_super_admin
from backend.services_v2.email_template_service import (
    EmailTemplateNotFoundError,
    EmailTemplateService,
    EmailTemplateValidationError,
    SUPPORTED_LANGUAGES,
)
from backend.utils.email_templates import EMAIL_TEMPLATE_VARIABLES, EMAIL_TEMPLATE_SAMPLE_VALUES


admin_email_templates_bp = Blueprint(
    "admin_email_templates_v2",
    __name__,
    url_prefix="/api/v2/admin/email-templates",
)


def _svc() -> EmailTemplateService:
    return current_app.config["EMAIL_TEMPLATE_SERVICE_V2"]


def _serialize(t) -> dict:
    return {
        "template_key": t.template_key,
        "language": t.language,
        "subject_template": t.subject_template,
        "body_template": t.body_template,
        "is_custom": t.is_custom,
        "created_at": t.created_at,
        "updated_at": t.updated_at,
        "updated_by_user_id": t.updated_by_user_id,
        "available_variables": list(EMAIL_TEMPLATE_VARIABLES.get(t.template_key, ())),
    }


def _check_language(language: str):
    if language not in SUPPORTED_LANGUAGES:
        return jsonify(
            {"error": f"Unsupported language: {language!r}. Supported: fr, en"}
        ), 400
    return None


@admin_email_templates_bp.get("")
def list_email_templates():
    ctx, err = require_super_admin()
    if err:
        return err

    templates = _svc().list_all()
    return jsonify([_serialize(t) for t in templates])


@admin_email_templates_bp.get("/<template_key>/<language>")
def get_email_template(template_key: str, language: str):
    ctx, err = require_super_admin()
    if err:
        return err

    lang_err = _check_language(language)
    if lang_err:
        return lang_err

    t = _svc().get(template_key, language)
    if t is None:
        return jsonify({"error": f"Template not found: {template_key}/{language}"}), 404

    return jsonify(_serialize(t))


@admin_email_templates_bp.put("/<template_key>/<language>")
def save_email_template(template_key: str, language: str):
    ctx, err = require_super_admin()
    if err:
        return err

    lang_err = _check_language(language)
    if lang_err:
        return lang_err

    data = request.get_json(silent=True) or {}
    subject = str(data.get("subject_template") or "").strip()
    body = str(data.get("body_template") or "").strip()

    try:
        t = _svc().upsert(
            template_key,
            language,
            subject,
            body,
            updated_by_user_id=ctx.user_id,
        )
    except EmailTemplateValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(_serialize(t))


@admin_email_templates_bp.post("/<template_key>/<language>/preview")
def preview_email_template(template_key: str, language: str):
    ctx, err = require_super_admin()
    if err:
        return err

    lang_err = _check_language(language)
    if lang_err:
        return lang_err

    data = request.get_json(silent=True) or {}
    subject_template = str(data.get("subject_template") or "").strip()
    body_template = str(data.get("body_template") or "").strip()

    svc = _svc()
    try:
        svc.validate(template_key, subject_template, body_template)
        sample = svc.get_sample_values(template_key)
        subject, body = svc.render_raw(subject_template, body_template, **sample)
    except EmailTemplateValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "subject": subject,
        "body": body,
        "sample_values": sample,
    })


@admin_email_templates_bp.post("/<template_key>/<language>/reset")
def reset_email_template(template_key: str, language: str):
    ctx, err = require_super_admin()
    if err:
        return err

    lang_err = _check_language(language)
    if lang_err:
        return lang_err

    try:
        t = _svc().reset(template_key, language)
    except (EmailTemplateValidationError, EmailTemplateNotFoundError) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(_serialize(t))
