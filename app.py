
import os

from flask import Flask, redirect, send_from_directory

from config import Settings
from backend.services_v2.job_service import JobService as JobServiceV2
from backend.routes_v2.jobs import jobs_v2_bp
from backend.routes_v2.dev import dev_v2_bp
from backend.services_v2.provider_config_service import ProviderConfigService
from backend.services_v2.destination_config_service import DestinationConfigService
from backend.routes_v2.providers import providers_v2_bp
from backend.routes_v2.destinations import destinations_v2_bp
from backend.routes_v2._context import ApiAuthError
from backend.routes_v2.me import me_v2_bp
from backend.services_v2.provider_factory import UserProviderFactory
from backend.routes_v2.provider_runtime import provider_runtime_v2_bp
from backend.services_v2.destination_factory import UserDestinationFactory
from backend.services_v2.crypto_service import CryptoService
from backend.routes_v2.settings import settings_v2_bp
from backend.repositories.factory import build_repositories
from backend.routes_v2.setup import setup_v2_bp
from backend.routes_v2.auth import auth_v2_bp
from backend.routes_v2.admin_users import admin_users_bp
from backend.routes_v2.system import system_v2_bp
from backend.services_v2.account_token_service import AccountTokenService
from backend.routes_v2.public_tokens import public_tokens_v2_bp
from backend.services_v2.smtp_service import SmtpService
from backend.routes_v2.admin_smtp import admin_smtp_bp
from backend.services_v2.app_settings_service import AppSettingsService
from backend.routes_v2.admin_app_settings import admin_app_settings_bp
from backend.services_v2.cleanup_service import CleanupService
from backend.services_v2.system_event_service import SystemEventService
from backend.routes_v2.admin_cleanup import admin_cleanup_bp
from backend.services_v2.maintenance_service import MaintenanceService
from backend.routes_v2.admin_maintenance import admin_maintenance_bp
from backend.routes_v2.admin_timeouts import admin_timeouts_bp
from backend.services_v2.notification_service import NotificationService
from backend.routes_v2.notifications import notifications_v2_bp
from backend.services_v2.notification_dispatcher_service import NotificationDispatcherService
from backend.routes_v2.admin_notifications import admin_notifications_bp
from backend.services_v2.rate_limit_service import RateLimitService
from backend.routes_v2.user_api_keys import user_api_keys_v2_bp
from backend.services_v2.user_api_key_service import UserApiKeyService
from backend.routes_v2.qbittorrent_compat import qbittorrent_compat_v2_bp
from backend.services_v2.user_integration_settings_service import UserIntegrationSettingsService
from backend.services_v2.single_user_service import SingleUserService
from backend.services_v2.announcement_service import AnnouncementService
from backend.routes_v2.announcements import announcements_v2_bp
from backend.routes_v2.admin_announcements import admin_announcements_bp
from backend.services_v2.email_template_service import EmailTemplateService
from backend.routes_v2.admin_email_templates import admin_email_templates_bp
from backend.routes_v2.admin_security import admin_security_v2_bp
from backend.routes_v2.public_files import public_files_v2_bp

def create_app() -> Flask:
    settings = Settings()
    settings.ensure_directories()


    app = Flask(
        __name__,
        static_folder="frontend",
        static_url_path="/frontend",
    )

    app.config["SETTINGS"] = settings
    app.config["SECRET_KEY"] = settings.FLASK_SECRET_KEY

    @app.get("/health")
    def health():
        return {"ok": True}, 200

    _NEXT_DIST = os.path.join(os.path.dirname(__file__), "frontend-next", "dist")
    _LEGACY_STATIC = os.path.join(os.path.dirname(__file__), "frontend")

    # 301 redirects for any bookmark/link still using the old /next prefix.
    @app.get("/next")
    @app.get("/next/")
    def redirect_next_root() -> object:
        return redirect("/", 301)

    @app.get("/next/<path:subpath>")
    def redirect_next_subpath(subpath: str) -> object:
        return redirect(f"/{subpath}", 301)

    app.config["RATE_LIMIT_SERVICE_V2"] = RateLimitService(
        enabled=settings.V2_RATE_LIMIT_ENABLED,
        redis_url=settings.REDIS_URL,
        redis_required=settings.V2_RATE_LIMIT_REDIS_REQUIRED,
    )

    @app.get("/")
    def serve_root() -> object:
        if not os.path.isdir(_NEXT_DIST):
            return (
                "Next UI is not built yet. Run: cd frontend-next && npm install && npm run build",
                503,
                {"Content-Type": "text/plain"},
            )
        return send_from_directory(_NEXT_DIST, "index.html")

    # Legacy UI — accessible at /legacy during the transition period.
    @app.get("/legacy")
    @app.get("/legacy/")
    @app.get("/legacy/<path:subpath>")
    def serve_legacy(subpath: str = "") -> object:
        if subpath and os.path.isfile(os.path.join(_LEGACY_STATIC, subpath)):
            return send_from_directory(_LEGACY_STATIC, subpath)
        return send_from_directory(_LEGACY_STATIC, "index.html")


    repositories_v2 = build_repositories(settings)

    user_repo_v2 = repositories_v2.user_repository
    job_repo_v2 = repositories_v2.job_repository
    provider_config_repo_v2 = repositories_v2.provider_config_repository
    destination_config_repo_v2 = repositories_v2.destination_config_repository
    api_token_repo_v2 = repositories_v2.api_token_repository
    user_api_key_repo_v2 = repositories_v2.user_api_key_repository
    user_integration_settings_repo_v2 = repositories_v2.user_integration_settings_repository
    external_client_submission_repo_v2 = repositories_v2.external_client_submission_repository

    account_token_repo_v2 = repositories_v2.account_token_repository
    smtp_settings_repo_v2 = repositories_v2.smtp_settings_repository
    app_settings_repo_v2 = repositories_v2.app_settings_repository

    notification_config_repo_v2 = repositories_v2.notification_config_repository
    notification_event_repo_v2 = repositories_v2.notification_event_repository

    app_settings_service_v2 = AppSettingsService(app_settings_repo_v2)

    user_destination_factory_v2 = UserDestinationFactory(
        destination_config_repository=destination_config_repo_v2,
        settings=settings,
    )

    user_provider_factory_v2 = UserProviderFactory(
        settings=settings,
        provider_config_repository=provider_config_repo_v2,
    )

    job_service_v2 = JobServiceV2(
        job_repository=job_repo_v2,
        provider_factory=user_provider_factory_v2,
        destination_factory=user_destination_factory_v2,
        app_settings_service=app_settings_service_v2,
    )

    provider_config_service_v2 = ProviderConfigService(provider_config_repo_v2)
    destination_config_service_v2 = DestinationConfigService(destination_config_repo_v2)

    crypto_service_v2 = CryptoService(settings.V2_SECRET_ENCRYPTION_KEY)

    app.config["USER_REPO_V2"] = user_repo_v2
    app.config["SINGLE_USER_SERVICE_V2"] = SingleUserService(
        user_repository=user_repo_v2,
        settings=settings,
    )

    app.config["JOB_SERVICE_V2"] = job_service_v2
    app.config["JOB_REPOSITORY_V2"] = job_repo_v2

    app.config["PROVIDER_CONFIG_SERVICE_V2"] = provider_config_service_v2
    app.config["DESTINATION_CONFIG_SERVICE_V2"] = destination_config_service_v2

    app.config["API_TOKEN_REPO_V2"] = api_token_repo_v2
    app.config["USER_API_KEY_REPO_V2"] = user_api_key_repo_v2
    app.config["USER_API_KEY_SERVICE_V2"] = UserApiKeyService(user_api_key_repo_v2)
    app.config["USER_INTEGRATION_SETTINGS_REPO_V2"] = user_integration_settings_repo_v2
    app.config["USER_INTEGRATION_SETTINGS_SERVICE_V2"] = UserIntegrationSettingsService(
        user_integration_settings_repo_v2,
    )    
    app.config["EXTERNAL_CLIENT_SUBMISSION_REPO_V2"] = external_client_submission_repo_v2
    app.config["ACCOUNT_TOKEN_REPO_V2"] = account_token_repo_v2
    app.config["SMTP_SETTINGS_REPO_V2"] = smtp_settings_repo_v2
    app.config["APP_SETTINGS_REPO_V2"] = app_settings_repo_v2
    app.config["NOTIFICATION_CONFIG_REPO_V2"] = notification_config_repo_v2
    app.config["NOTIFICATION_EVENT_REPO_V2"] = notification_event_repo_v2
    app.config["CRYPTO_SERVICE_V2"] = crypto_service_v2

    app.config["SMTP_SERVICE_V2"] = SmtpService(
        smtp_settings_repo_v2,
        crypto_service_v2,
    )

    app.config["NOTIFICATION_SERVICE_V2"] = NotificationService(
        notification_config_repository=repositories_v2.notification_config_repository,
        notification_rule_repository=repositories_v2.notification_rule_repository,
        notification_event_repository=repositories_v2.notification_event_repository,
        crypto_service=crypto_service_v2,
        smtp_service=app.config["SMTP_SERVICE_V2"],
        user_repository=user_repo_v2,
    )

    job_service_v2.notification_service = app.config["NOTIFICATION_SERVICE_V2"]

    app.config["NOTIFICATION_DISPATCHER_SERVICE_V2"] = NotificationDispatcherService(
        notification_config_repository=repositories_v2.notification_config_repository,
        notification_event_repository=repositories_v2.notification_event_repository,
        notification_rule_repository=repositories_v2.notification_rule_repository,
        notification_service=app.config["NOTIFICATION_SERVICE_V2"],
        crypto_service=crypto_service_v2,
        smtp_service=app.config["SMTP_SERVICE_V2"],
        user_repository=user_repo_v2,
        app_settings_service=app_settings_service_v2,
        job_repository=job_repo_v2,
    )
    app.config["ACCOUNT_TOKEN_SERVICE_V2"] = AccountTokenService(
        account_token_repo_v2,
        public_base_url=getattr(settings, "PUBLIC_BASE_URL", None),
        app_settings_service=app_settings_service_v2,
    )

    app.config["APP_SETTINGS_SERVICE_V2"] = app_settings_service_v2

    app.config["SYSTEM_EVENT_SERVICE_V2"] = SystemEventService(
        app_settings_service=app.config["APP_SETTINGS_SERVICE_V2"],
        notification_service=app.config["NOTIFICATION_SERVICE_V2"],
        notification_event_repository=repositories_v2.notification_event_repository,
        user_repository=repositories_v2.user_repository,
    )
    app.config["CLEANUP_SERVICE_V2"] = CleanupService(
        settings=settings,
        app_settings_service=app.config["APP_SETTINGS_SERVICE_V2"],
        job_repository=job_repo_v2,
        account_token_repository=account_token_repo_v2,
    )
    app.config["MAINTENANCE_SERVICE_V2"] = MaintenanceService(
        settings=settings,
        db=repositories_v2.db,
        app_settings_service=app_settings_service_v2,
    )
    app.config["USER_PROVIDER_FACTORY_V2"] = user_provider_factory_v2
    app.config["USER_DESTINATION_FACTORY_V2"] = user_destination_factory_v2

    app.config["EMAIL_TEMPLATE_SERVICE_V2"] = EmailTemplateService(
        email_template_repository=repositories_v2.email_template_repository,
    )
    app.config["EMAIL_TEMPLATE_SERVICE_V2"].ensure_defaults()

    app.config["NOTIFICATION_DISPATCHER_SERVICE_V2"].email_template_service = (
        app.config["EMAIL_TEMPLATE_SERVICE_V2"]
    )

    app.config["NOTIFICATION_SERVICE_V2"].email_template_service = (
        app.config["EMAIL_TEMPLATE_SERVICE_V2"]
    )
    app.config["NOTIFICATION_SERVICE_V2"].app_settings_service = app_settings_service_v2

    app.config["ANNOUNCEMENT_SERVICE_V2"] = AnnouncementService(
        announcement_repository=repositories_v2.announcement_repository,
        announcement_read_repository=repositories_v2.announcement_read_repository,
        user_repository=user_repo_v2,
        smtp_service=app.config["SMTP_SERVICE_V2"],
        app_settings_service=app_settings_service_v2,
        email_template_service=app.config["EMAIL_TEMPLATE_SERVICE_V2"],
    )

    app.register_blueprint(setup_v2_bp)
    app.register_blueprint(auth_v2_bp)
    app.register_blueprint(settings_v2_bp)
    app.register_blueprint(system_v2_bp)
    app.register_blueprint(jobs_v2_bp)
    app.register_blueprint(providers_v2_bp)
    app.register_blueprint(destinations_v2_bp)
    app.register_blueprint(notifications_v2_bp)
    app.register_blueprint(me_v2_bp)
    app.register_blueprint(user_api_keys_v2_bp)
    app.register_blueprint(qbittorrent_compat_v2_bp)
    app.register_blueprint(provider_runtime_v2_bp)
    app.register_blueprint(admin_users_bp)
    app.register_blueprint(public_tokens_v2_bp)
    app.register_blueprint(admin_smtp_bp)
    app.register_blueprint(admin_app_settings_bp)
    app.register_blueprint(admin_cleanup_bp)
    app.register_blueprint(admin_maintenance_bp)
    app.register_blueprint(admin_timeouts_bp)
    app.register_blueprint(admin_notifications_bp)
    app.register_blueprint(announcements_v2_bp)
    app.register_blueprint(admin_announcements_bp)
    app.register_blueprint(admin_email_templates_bp)
    app.register_blueprint(admin_security_v2_bp)
    app.register_blueprint(public_files_v2_bp)

    if settings.DEBUG and settings.V2_DEV_ROUTES_ENABLED:
        app.register_blueprint(dev_v2_bp)

    # /invite and /verify-email are not yet in the Next UI router — serve legacy temporarily.
    @app.get("/invite")
    @app.route("/verify-email")
    def serve_legacy_token_pages() -> object:
        return send_from_directory(_LEGACY_STATIC, "index.html")

    # SPA fallback — Next UI assets and all unmatched routes.
    @app.get("/<path:subpath>")
    def serve_next_spa(subpath: str) -> object:
        if not os.path.isdir(_NEXT_DIST):
            return (
                "Next UI is not built yet. Run: cd frontend-next && npm install && npm run build",
                503,
                {"Content-Type": "text/plain"},
            )
        asset_path = os.path.join(_NEXT_DIST, subpath)
        if os.path.isfile(asset_path):
            return send_from_directory(_NEXT_DIST, subpath)
        return send_from_directory(_NEXT_DIST, "index.html")

    @app.errorhandler(ApiAuthError)
    def handle_api_auth_error(error):
        return {"error": error.message}, 401

    return app


app = create_app()

if __name__ == "__main__":
    settings = app.config["SETTINGS"]
    app.run(host=settings.HOST, port=settings.PORT, debug=settings.DEBUG)
