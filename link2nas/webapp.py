# link2nas/webapp.py
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime

import redis
from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from .web_admin_tools import register_admin_tools_routes

from . import redis_store as rs
from .config import Settings
from .status import get_premium_info_cached
from .status_checks import build_status_snapshot
from .web_auth import make_require_admin
from .web_helpers import env_bool, mk_error, payload_items, redact_url, sanitize_body, scrub_for_log
from .web_process import WebProcessor


def create_app(s: Settings, template_folder: str | None = None, static_folder: str | None = None) -> Flask:
    """
    Flask app + routes.
    Everything else lives in dedicated web_* modules.
    """
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    app.config["SECRET_KEY"] = s.flask_secret_key
    CORS(app, origins=s.cors_origins)

    logger = logging.getLogger("link2nas.webapp")
    rdb = redis.Redis(host=s.redis_host, port=s.redis_port, db=s.redis_db)

    require_admin = make_require_admin(s)
    processor = WebProcessor(s, rdb, logger)

    register_admin_tools_routes(app, s, rdb, logger, require_admin)

    # ============================================================
    # Request logging
    # ============================================================

    @app.before_request
    def log_request_begin():
        g.rid = uuid.uuid4().hex[:8]
        g.t0 = time.time()

        if request.path in (s.noisy_paths or set()):
            return

        ct = request.headers.get("Content-Type", "")
        has_auth = bool(request.headers.get("Authorization"))
        body = ""

        if env_bool("WEB_LOG_BODY", False):
            body = sanitize_body(request.get_data(cache=True, as_text=True) or "")

        logger.info(
            "[RID %s] %s %s %s CT=%s Auth=%s body=%r",
            g.rid,
            request.remote_addr,
            request.method,
            request.path,
            ct,
            ("yes" if has_auth else "no"),
            body,
        )

    @app.after_request
    def log_request_end(resp):
        try:
            if request.path in (s.noisy_paths or set()):
                return resp
            dt_ms = int((time.time() - getattr(g, "t0", time.time())) * 1000)
            logger.info("[RID %s] -> %s (%dms)", getattr(g, "rid", "--------"), resp.status_code, dt_ms)
        except Exception:
            pass
        return resp

    @app.errorhandler(Exception)
    def on_exception(e):
        if isinstance(e, HTTPException):
            return e
        rid = getattr(g, "rid", "--------")
        logger.error("[RID %s] unhandled: %s", rid, e, exc_info=True)
        payload = {"success": False, "error": "Internal error", "rid": rid}
        if app.debug:
            payload["exception"] = type(e).__name__
            payload["message"] = str(e)
        return jsonify(payload), 500

    # ============================================================
    # Template helpers
    # ============================================================

    @app.context_processor
    def inject_now_helpers():
        return {"datetime": datetime}

    @app.template_filter("timestamp_to_datetime")
    def timestamp_to_datetime(timestamp):
        try:
            return datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""

    # ============================================================
    # UI context builder (index/admin)
    # ============================================================

    def build_index_context(is_admin: bool = False):
        def _safe_int(x, default=0) -> int:
            try:
                return int(float(x))
            except Exception:
                return default

        def _safe_float(x, default=0.0) -> float:
            try:
                return float(x)
            except Exception:
                return default

        pending_torrents = []
        completed_torrents = []

        keys = rs.iter_all_items_keys(rdb)
        for k in keys:
            key_str = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)
            kind, item_id = rs.redis_key_id(key_str)

            try:
                data = rdb.hgetall(k)
                if not data:
                    continue
                decoded = rs.decode_hash(data)

                status = (decoded.get("status") or "unknown").strip().lower()
                size = _safe_int(decoded.get("size", "0"), 0)
                downloaded = _safe_int(decoded.get("downloaded", "0"), 0)

                progress_raw = _safe_float(decoded.get("progress", "0"), 0.0)
                if progress_raw <= 0 and size > 0 and downloaded > 0:
                    progress_raw = (downloaded / max(size, 1)) * 100.0
                progress = min(max(progress_raw, 0.0), 100.0)

                links_count = _safe_int(decoded.get("links_count", "0"), 0)
                links = rs.parse_links_dicts(decoded)

                app_status = (decoded.get("app_status") or "").strip()
                nas_error = (decoded.get("nas_error") or "").strip()

                torrent_info = {
                    "id": item_id,
                    "kind": kind,
                    "name": decoded.get("name", "Inconnu"),
                    "status": status,
                    "progress": progress,
                    "size": size,
                    "downloaded": downloaded,
                    "timestamp": _safe_float(decoded.get("timestamp", time.time()), time.time()),
                    "type": kind,
                    "links": links,
                    "links_count": links_count,
                    "app_status": app_status,
                    "nas_error": nas_error,
                }

                if links_count > 0:
                    completed_torrents.append(torrent_info)
                else:
                    pending_torrents.append(torrent_info)

            except Exception as e:
                logger.error("Erreur traitement item %s: %s", key_str, str(e), exc_info=True)

        pending_torrents.sort(key=lambda x: x["timestamp"], reverse=True)
        completed_torrents.sort(key=lambda x: x["timestamp"], reverse=True)

        all_completed_links = []
        if is_admin:
            all_completed_links = [
                f.get("link")
                for t in completed_torrents
                for f in (t.get("links") or [])
                if isinstance(f, dict) and f.get("link")
            ]

        ctx = dict(
            pending_torrents=pending_torrents,
            completed_torrents=completed_torrents,
            all_completed_links=all_completed_links,
            pending_refresh_url=url_for("api_pending_torrents"),
            completed_refresh_url=url_for("api_completed_torrents"),
            is_admin=is_admin,
        )
        if is_admin:
            ctx["alldebrid_premium"] = get_premium_info_cached(s, rdb, ttl_seconds=300)
        return ctx

    # ============================================================
    # UI routes
    # ============================================================

    @app.route("/", methods=["GET", "POST"])
    def index():
        if request.method == "POST":
            lines = [l.strip() for l in (request.form.get("magnet_links", "") or "").splitlines() if l.strip()]
            logger.info("[PUBLIC] lignes reçues: %s", len(lines))

            max_items = int(getattr(s, "max_items_per_submit", 200) or 200)
            if len(lines) > max_items:
                flash(f"{len(lines)} entrées — limite {max_items} pour éviter le rate limit AllDebrid.", "error")
                return redirect(url_for("index"))

            if not lines:
                flash("Aucune entrée fournie", "error")
                return redirect(url_for("index"))

            for line in lines:
                try:
                    created, err, _st = processor.process_one_item_public(line)
                    if created:
                        kind = created.get("kind", "item")
                        name = created.get("name") or redact_url(line)
                        extra = ""
                        if kind == "direct" and (created.get("link_ready") or created.get("link")):
                            extra = " (lien prêt)"
                        if created.get("links_count", 0):
                            extra = f" ({created.get('links_count')} liens)"
                        flash(f"OK [{kind}] : {name}{extra}", "success")
                    else:
                        err = err or {"code": "UNKNOWN", "message": "Erreur inconnue"}
                        flash(f"Erreur : {err.get('code','UNKNOWN')} - {err.get('message','')}", "warning")
                except Exception as e:
                    logger.error("[PUBLIC] Erreur traitement ligne %s: %s", redact_url(line), str(e), exc_info=True)
                    flash("Erreur interne (voir logs).", "warning")

            return redirect(url_for("index"))

        return render_template("index.html", **build_index_context(is_admin=False))

    @app.route("/admin", methods=["GET", "POST"])
    @require_admin
    def admin():
        if not (getattr(s, "admin_ui_enabled", True) and s.nas_enabled):
            abort(404)

        if request.method == "POST":
            action = (request.form.get("action") or "generate").strip()
            should_send = action == "generate_and_send"

            lines = [l.strip() for l in (request.form.get("magnet_links", "") or "").splitlines() if l.strip()]
            logger.info("[ADMIN] action=%s lignes reçues: %s", action, len(lines))

            max_items = int(getattr(s, "max_items_per_submit", 200) or 200)
            if len(lines) > max_items:
                flash(f"{len(lines)} entrées — limite {max_items} pour éviter le rate limit AllDebrid.", "error")
                return redirect(url_for("admin"))

            if should_send:
                flash("Envoi NAS demandé : direct = envoi immédiat, magnet = planifié (scheduler).", "info")

            for line in lines:
                try:
                    created, err, _st = (
                        processor.process_one_item_admin(line) if should_send else processor.process_one_item_public(line)
                    )

                    if created:
                        kind = created.get("kind", "item")
                        name = created.get("name") or redact_url(line)
                        extra = ""
                        if kind == "direct" and (created.get("link_ready") or created.get("link")):
                            extra = " (lien prêt)"
                        if created.get("links_count", 0):
                            extra = f" ({created.get('links_count')} liens)"
                        if created.get("nas") == "sent":
                            extra = " (NAS envoyé)"
                        if created.get("nas") == "scheduled":
                            extra = " (NAS planifié)"
                        if created.get("nas") == "failed":
                            extra = " (NAS échec)"
                        flash(f"OK [{kind}] : {name}{extra}", "success")
                    else:
                        err = err or {"code": "UNKNOWN", "message": "Erreur inconnue"}
                        flash(f"Erreur : {err.get('code','UNKNOWN')} - {err.get('message','')}", "warning")

                except Exception as e:
                    logger.error("[ADMIN] Erreur traitement ligne %s: %s", redact_url(line), str(e), exc_info=True)
                    flash("Erreur interne (voir logs).", "warning")

            return redirect(url_for("admin"))

        return render_template("index.html", **build_index_context(is_admin=True))

    # ============================================================
    # Status routes
    # ============================================================

    @app.route("/status", methods=["GET"])
    @require_admin
    def status_page():
        if not bool(getattr(s, "status_route_enabled", True)):
            abort(404)

        snap = build_status_snapshot(s, rdb)
        return render_template(
            "status.html",
            now=snap["now"],
            overall=snap["overall"],
            ad_ping_ok=snap["ad_ping_ok"],
            ad_ping=snap["ad_ping"],
            ad_endpoints=snap["ad_endpoints"],
            premium=snap["premium"],
            premium_days_left=snap["premium_days_left"],
            premium_color=snap["premium_color"],
            premium_label=snap["premium_label"],
            redis_info=snap["redis_info"],
            nas_info=snap["nas_info"],
            NAS_ENABLED=bool(s.nas_enabled),
        )

    # ============================================================
    # API routes
    # ============================================================

    @app.route("/api/capabilities", methods=["GET"])
    def api_capabilities():
        return jsonify({"success": True, "version": s.app_version, "capabilities": {"nas_enabled": bool(s.nas_enabled)}})

    @app.route("/api/submit", methods=["POST"])
    def api_submit():
        payload = request.get_json(force=True, silent=True) or {}
        items = payload_items(payload)
        if not items:
            return (
                jsonify(
                    {
                        "success": False,
                        "created": [],
                        "errors": [mk_error("", {"kind": "bad_request", "code": "EMPTY_URL", "message": "url required"})],
                    }
                ),
                400,
            )

        created, errors = [], []
        worst_status = 400
        for it in items:
            c, e, st = processor.process_one_item_public(it)
            if c:
                created.append(c)
            else:
                errors.append(mk_error(it, e or {"kind": "unknown", "code": "UNKNOWN", "message": "error"}))
                if st and st > worst_status:
                    worst_status = st

        success = len(created) > 0
        return jsonify({"success": success, "created": created, "errors": errors}), (200 if success else worst_status)

    @app.route("/api/admin/submit_and_send", methods=["POST", "OPTIONS"])
    @require_admin
    def api_admin_submit_and_send():
        if not s.nas_enabled:
            return (
                jsonify(
                    {
                        "success": False,
                        "created": [],
                        "errors": [
                            mk_error(
                                "",
                                {"kind": "forbidden", "code": rs.NAS_ERROR_NAS_DISABLED, "message": "NAS feature is disabled."},
                            )
                        ],
                    }
                ),
                403,
            )

        payload = request.get_json(force=True, silent=True) or {}
        items = payload_items(payload)
        if not items:
            return (
                jsonify(
                    {
                        "success": False,
                        "created": [],
                        "errors": [mk_error("", {"kind": "bad_request", "code": "EMPTY_URL", "message": "url required"})],
                    }
                ),
                400,
            )

        created, errors = [], []
        worst_status = 400
        for it in items:
            c, e, st = processor.process_one_item_admin(it)
            if c:
                created.append(c)
            else:
                errors.append(mk_error(it, e or {"kind": "unknown", "code": "UNKNOWN", "message": "error"}))
                if st and st > worst_status:
                    worst_status = st

        success = len(created) > 0
        return jsonify({"success": success, "created": created, "errors": errors}), (200 if success else worst_status)

    @app.route("/api/pending_torrents", methods=["GET"])
    def api_pending_torrents():
        def _safe_int(x, default=0) -> int:
            try:
                return int(float(x))
            except Exception:
                return default

        def _safe_float(x, default=0.0) -> float:
            try:
                return float(x)
            except Exception:
                return default

        torrents = []
        keys = rs.iter_all_items_keys(rdb)

        for k in keys:
            key_str = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)
            kind, item_id = rs.redis_key_id(key_str)

            data = rdb.hgetall(k)
            if not data:
                continue
            decoded = rs.decode_hash(data)

            status = (decoded.get("status") or "unknown").strip().lower()
            links_count = _safe_int(decoded.get("links_count", "0"), 0)
            if links_count > 0:
                continue

            size = _safe_int(decoded.get("size", "0"), 0)
            downloaded = _safe_int(decoded.get("downloaded", "0"), 0)

            progress_raw = _safe_float(decoded.get("progress", "0"), 0.0)
            if progress_raw <= 0 and size > 0 and downloaded > 0:
                progress_raw = (downloaded / max(size, 1)) * 100.0
            progress = min(max(progress_raw, 0.0), 100.0)

            torrents.append(
                {
                    "id": item_id,
                    "kind": kind,
                    "type": (decoded.get("type") or kind),
                    "name": decoded.get("name", "Nom inconnu"),
                    "status": status,
                    "progress": progress,
                    "size": size,
                    "downloaded": downloaded,
                    "timestamp": _safe_float(decoded.get("timestamp", time.time()), time.time()),
                    "links": rs.parse_links_dicts(decoded),
                    "links_count": links_count,
                    "app_status": (decoded.get("app_status") or "").strip(),
                    "nas_error": (decoded.get("nas_error") or "").strip(),
                    "sent_to_nas": (decoded.get("sent_to_nas") or "false").strip().lower(),
                    "sent_to_nas_at": (decoded.get("sent_to_nas_at") or "").strip(),
                    "nas_last_attempt": (decoded.get("nas_last_attempt") or "").strip(),
                }
            )

        return jsonify(torrents)

    @app.route("/api/completed_torrents", methods=["GET"])
    def api_completed_torrents():
        def _safe_int(x, default=0) -> int:
            try:
                return int(float(x))
            except Exception:
                return default

        def _safe_float(x, default=0.0) -> float:
            try:
                return float(x)
            except Exception:
                return default

        torrents = []
        keys = rs.iter_all_items_keys(rdb)

        for k in keys:
            key_str = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)
            kind, item_id = rs.redis_key_id(key_str)

            data = rdb.hgetall(k)
            if not data:
                continue
            decoded = rs.decode_hash(data)

            status = (decoded.get("status") or "unknown").strip().lower()
            links_count = _safe_int(decoded.get("links_count", "0"), 0)
            if links_count <= 0:
                continue

            links = rs.parse_links_dicts(decoded)
            size = _safe_int(decoded.get("size", "0"), 0)
            downloaded = _safe_int(decoded.get("downloaded", "0"), 0)

            progress_raw = _safe_float(decoded.get("progress", "100"), 100.0)
            if progress_raw <= 0 and size > 0 and downloaded > 0:
                progress_raw = (downloaded / max(size, 1)) * 100.0
            progress = min(max(progress_raw, 0.0), 100.0)

            torrents.append(
                {
                    "id": item_id,
                    "kind": kind,
                    "type": (decoded.get("type") or kind),
                    "name": decoded.get("name", "Nom inconnu"),
                    "status": status,
                    "progress": progress,
                    "size": size,
                    "downloaded": downloaded,
                    "timestamp": _safe_float(decoded.get("timestamp", time.time()), time.time()),
                    "links": links,
                    "links_count": links_count,
                    "app_status": (decoded.get("app_status") or "").strip(),
                    "nas_error": (decoded.get("nas_error") or "").strip(),
                    "sent_to_nas": (decoded.get("sent_to_nas") or "false").strip().lower(),
                    "sent_to_nas_at": (decoded.get("sent_to_nas_at") or "").strip(),
                    "nas_last_attempt": (decoded.get("nas_last_attempt") or "").strip(),
                }
            )

        return jsonify(torrents)

    @app.route("/api/status", methods=["GET"])
    @require_admin
    def status_api():
        if not bool(getattr(s, "status_route_enabled", True)):
            abort(404)
        snap = build_status_snapshot(s, rdb)
        return jsonify(
            {
                "now": snap["now"].isoformat(),
                "overall": snap["overall"],
                "ad_ping_ok": snap["ad_ping_ok"],
                "ad_ping": snap["ad_ping"],
                "ad_endpoints": snap["ad_endpoints"],
                "premium": snap["premium"],
                "premium_days_left": snap["premium_days_left"],
                "premium_color": snap["premium_color"],
                "premium_label": snap["premium_label"],
                "redis_info": snap["redis_info"],
                "nas_info": snap["nas_info"],
                "nas_enabled": bool(s.nas_enabled),
            }
        )

    # ============================================================
    # Admin debug routes (debug only)
    # ============================================================

    @app.route("/debug_redis", methods=["GET"])
    @require_admin
    def debug_redis():
        if not current_app.debug:
            abort(404)

        try:
            keys = rs.iter_all_items_keys(rdb)
            debug_info = []
            for k in keys:
                key_str = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)
                data = rdb.hgetall(k)
                decoded_data = rs.decode_hash(data)
                debug_info.append({"key": key_str, "data": scrub_for_log(decoded_data)})
            return render_template("debug_redis.html", torrents=debug_info)
        except Exception as e:
            logger.error("Erreur debug_redis: %s", str(e), exc_info=True)
            return f"Erreur: {str(e)}", 500

    # ============================================================
    # Admin action routes
    # ============================================================

    @app.route("/send_to_nas/<torrent_id>", methods=["POST"])
    @require_admin
    def send_to_nas(torrent_id: str):
        """
        Support:
          - magnet:<id>  => planifie (nas_pending), scheduler envoie plus tard
          - direct:<id>  => envoi immédiat
          - <id>         => essaie magnet:<id>, puis direct:<id>
        """
        try:
            tid = (torrent_id or "").strip()
            if tid.startswith("magnet:") or tid.startswith("direct:"):
                candidates = [tid]
            else:
                candidates = [f"magnet:{tid}", f"direct:{tid}"]

            found_key = None
            found_kind = None
            found_id = None

            for key_str in candidates:
                if rdb.exists(key_str):
                    found_key = key_str
                    found_kind, found_id = rs.redis_key_id(key_str)
                    break

            logger.info(
                "[NAS][WEB] send_to_nas tid=%r candidates=%s found_key=%r found_kind=%r found_id=%r",
                torrent_id,
                candidates,
                found_key,
                found_kind,
                found_id,
            )
            if not found_key:
                return jsonify({"success": False, "error": "Item non trouvé"}), 404

            app_status_b = rdb.hget(found_key, "app_status")
            app_status = (app_status_b or b"").decode("utf-8", "ignore").strip()

            if app_status == rs.APP_STATUS_NAS_SENT:
                return jsonify({"success": True, "message": "Déjà envoyé au NAS."})

            if found_kind == "magnet":
                rdb.hset(
                    found_key,
                    mapping={"app_status": rs.APP_STATUS_NAS_PENDING, "nas_requested_at": str(time.time()), "nas_error": ""},
                )
                return jsonify({"success": True, "message": "Envoi au NAS planifié (scheduler)."})

            if not found_id:
                return jsonify({"success": False, "error": "ID direct manquant"}), 500

            ok_send, send_err = processor.send_direct_now(found_id)
            if ok_send:
                return jsonify({"success": True, "message": "Lien(s) envoyé(s) au NAS."})
            code = (send_err or {}).get("code") or "NAS_SEND_FAILED"
            msg = (send_err or {}).get("message") or "send_failed"
            return jsonify({"success": False, "error": f"{code}: {msg}"}), 502

        except Exception as e:
            logger.error("Erreur send_to_nas: %s", str(e), exc_info=True)
            return jsonify({"success": False, "error": f"Erreur: {str(e)}"}), 500

    return app
