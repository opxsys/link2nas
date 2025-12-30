from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
import uuid
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

import redis
import requests
from flask import (
    Flask,
    Response,
    abort,
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

from .config import Settings
from . import redis_store as rs
from .alldebrid import upload_magnet_safe, unlock_link_safe
from .synology import send_to_download_station_safe
from .status import get_premium_info_cached

def create_app(s: Settings, template_folder: str | None = None, static_folder: str | None = None) -> Flask:
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)

    app.config["SECRET_KEY"] = s.flask_secret_key
    CORS(app, origins=s.cors_origins)

    logging.basicConfig(
        level=getattr(logging, s.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logger = logging.getLogger("link2nas.webapp")

    rdb = redis.Redis(host=s.redis_host, port=s.redis_port, db=s.redis_db)

    # -------------------------
    # Logging helpers
    # -------------------------
    def sanitize_body(body: str) -> str:
        body = (body or "").strip()
        if not body:
            return ""
        if len(body) > 800:
            body = body[:800] + "…(truncated)"
        body = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*", r"\1***", body)
        body = re.sub(
            r'(?i)("?(?:api[_-]?key|token|access[_-]?token|refresh[_-]?token|password|passwd|sid)"?\s*:\s*)"([^"]*)"',
            r'\1"***"',
            body,
        )
        body = re.sub(
            r"(?i)((?:api[_-]?key|token|access[_-]?token|refresh[_-]?token|password|passwd|sid)\s*=\s*)([^&\s]+)",
            r"\1***",
            body,
        )
        body = re.sub(r"(?i)magnet:\?[^ \r\n\t\"']+", "magnet:?***", body)
        body = re.sub(r"(?i)\bhttps?://[^\s\"']+", "https://***", body)
        return body.replace("\r", "\\r").replace("\n", "\\n")

    @app.before_request
    def log_request_begin():
        g.rid = uuid.uuid4().hex[:8]
        g.t0 = time.time()
        if request.path in (s.noisy_paths or set()):
            return
        ct = request.headers.get("Content-Type", "")
        has_auth = bool(request.headers.get("Authorization"))
        body = ""
        if app.debug:
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

    # -------------------------
    # Admin auth
    # -------------------------
    def unauthorized():
        return Response(
            "Auth required",
            401,
            {"WWW-Authenticate": f'Basic realm="{s.admin_realm}", charset="UTF-8"'},
        )

    def require_admin(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.method == "OPTIONS":
                return ("", 204)
            if not s.admin_enabled:
                abort(404)
            if not s.admin_pass:
                return unauthorized()
            auth = request.authorization
            if not auth:
                return unauthorized()
            ok_user = secrets.compare_digest(auth.username or "", s.admin_user)
            ok_pass = secrets.compare_digest(auth.password or "", s.admin_pass)
            if not (ok_user and ok_pass):
                return unauthorized()
            return f(*args, **kwargs)

        return wrapper

    # -------------------------
    # Input helpers
    # -------------------------
    def is_magnet(x: str) -> bool:
        return (x or "").strip().lower().startswith("magnet:?")

    def is_http_url(x: str) -> bool:
        try:
            u = urlparse((x or "").strip())
            return u.scheme in {"http", "https"} and bool(u.netloc)
        except Exception:
            return False

    def payload_items(payload: dict) -> list[str]:
        payload = payload or {}
        items = payload.get("items", None)
        url = (payload.get("url") or "").strip()

        out: list[str] = []
        if isinstance(items, list):
            out = [str(x).strip() for x in items if str(x).strip()]
        elif isinstance(items, str) and items.strip():
            out = [items.strip()]
        elif url:
            out = [url]

        seen = set()
        uniq = []
        for it in out:
            if it not in seen:
                seen.add(it)
                uniq.append(it)
        return uniq

    def mk_created(item: str, kind: str, _id: str, name: str, extra: dict | None = None) -> dict:
        d = {"item": item, "kind": kind, "id": str(_id), "name": name}
        if extra:
            d.update(extra)
        return d

    def mk_error(item: str, err: dict) -> dict:
        return {"item": item, "error": err}

    def normalize_input_error(_: str) -> dict:
        return {"kind": "bad_request", "code": "UNSUPPORTED_INPUT", "message": "Only magnet or http(s) urls"}

    # -------------------------
    # Item processing
    # -------------------------
    def process_one_item_public(item: str):
        if is_magnet(item):
            ok, data_or_err = upload_magnet_safe(s, item)
            if not ok:
                return None, data_or_err, 422
            mid = data_or_err["id"]
            name = data_or_err["name"]
            rs.store_magnet(rdb, mid, name, app_status="")
            return mk_created(item, "magnet", str(mid), name), None, None

        if is_http_url(item):
            ok, data_or_err = unlock_link_safe(s, item)
            if not ok:
                return None, data_or_err, 422
            unlocked_link = (data_or_err.get("link") or "").strip()
            filename = (data_or_err.get("filename") or "").strip() or "direct_link"
            filesize = int(data_or_err.get("filesize") or 0)
            direct_id = str(data_or_err.get("id") or int(time.time() * 1000))
            rs.store_direct(
                rdb,
                direct_id,
                filename,
                filesize,
                unlocked_link,
                app_status=rs.APP_STATUS_DISPLAY_READY,
            )
            return mk_created(item, "direct", direct_id, filename, {"link": unlocked_link}), None, None

        return None, normalize_input_error(item), 400

    def process_one_item_admin(item: str):
        if is_magnet(item):
            ok, data_or_err = upload_magnet_safe(s, item)
            if not ok:
                return None, data_or_err, 422
            mid = data_or_err["id"]
            name = data_or_err["name"]
            rs.store_magnet(rdb, mid, name, app_status=rs.APP_STATUS_NAS_PENDING)
            return mk_created(item, "magnet", str(mid), name, {"nas": "scheduled"}), None, None

        if is_http_url(item):
            ok, data_or_err = unlock_link_safe(s, item)
            if not ok:
                return None, data_or_err, 422

            unlocked_link = (data_or_err.get("link") or "").strip()
            filename = (data_or_err.get("filename") or "").strip() or "direct_link"
            filesize = int(data_or_err.get("filesize") or 0)
            direct_id = str(data_or_err.get("id") or int(time.time() * 1000))

            if not s.nas_enabled:
                rs.store_direct(
                    rdb,
                    direct_id,
                    filename,
                    filesize,
                    unlocked_link,
                    app_status=rs.APP_STATUS_NAS_DISABLED,
                    sent_to_nas=False,
                    nas_error=rs.NAS_ERROR_NAS_DISABLED,
                )
                return None, {"kind": "forbidden", "code": rs.NAS_ERROR_NAS_DISABLED, "message": "NAS disabled by configuration"}, 403

            ok_send, send_err = send_to_download_station_safe(s, [unlocked_link])
            if ok_send:
                rs.store_direct(
                    rdb,
                    direct_id,
                    filename,
                    filesize,
                    unlocked_link,
                    app_status=rs.APP_STATUS_NAS_SENT,
                    sent_to_nas=True,
                )
                return mk_created(item, "direct", direct_id, filename, {"nas": "sent"}), None, None

            rs.store_direct(
                rdb,
                direct_id,
                filename,
                filesize,
                unlocked_link,
                app_status=rs.APP_STATUS_NAS_FAILED,
                sent_to_nas=False,
                nas_error=(send_err or {}).get("code", "NAS_SEND_FAILED"),
            )
            return None, send_err, 502

        return None, normalize_input_error(item), 400

    # -------------------------
    # Template helpers
    # -------------------------
    @app.context_processor
    def inject_now_helpers():
        return {"datetime": datetime}

    @app.template_filter("timestamp_to_datetime")
    def timestamp_to_datetime(timestamp):
        try:
            return datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""

    # -------------------------
    # UI context builder
    # -------------------------
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

                # PROGRESS: si champ progress est foireux ou non rempli, calcule fallback
                progress_raw = _safe_float(decoded.get("progress", "0"), 0.0)
                if progress_raw <= 0 and size > 0 and downloaded > 0:
                    progress_raw = (downloaded / max(size, 1)) * 100.0
                progress = min(max(progress_raw, 0.0), 100.0)

                # IMPORTANT: ne plus recalculer links_count via len(parse_links_dicts())
                links_count = _safe_int(decoded.get("links_count", "0"), 0)
                links = rs.parse_links_dicts(decoded)  # seulement pour affichage

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

                # Règle stable : completed = links_count > 0 (peu importe status exact)
                if links_count > 0:
                    completed_torrents.append(torrent_info)
                else:
                    pending_torrents.append(torrent_info)

            except Exception as e:
                logger.error("Erreur traitement item %s: %s", key_str, str(e), exc_info=True)
                continue

        pending_torrents.sort(key=lambda x: x["timestamp"], reverse=True)
        completed_torrents.sort(key=lambda x: x["timestamp"], reverse=True)

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

        return ctx





    # -------------------------
    # Status helpers (/status)
    # -------------------------
    def _join_url(base: str, path: str) -> str:
        base = (base or "").rstrip("/")
        path = (path or "").strip()
        if not path.startswith("/"):
            path = "/" + path
        return base + path

    def _alldebrid_endpoint_is_discontinued(js: dict | None) -> bool:
        if not isinstance(js, dict):
            return False
        err = js.get("error")
        if not isinstance(err, dict):
            return False
        return err.get("code") == "DISCONTINUED"

    def _ad_request(method: str, path: str, data: dict | None = None, timeout: int | None = None) -> tuple[bool, dict]:
        """
        Wrapper AllDebrid pour /status : détecte DISCONTINUED + timeout/network.
        Ne renvoie aucun secret.
        """
        url = _join_url(s.alldebrid_base_url, path)
        headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}

        try:
            r = requests.request(method=method, url=url, headers=headers, data=data, timeout=timeout or 6)

            js = None
            try:
                js = r.json()
            except Exception:
                js = None

            if _alldebrid_endpoint_is_discontinued(js):
                return False, {
                    "ok": False,
                    "kind": "discontinued",
                    "code": "DISCONTINUED",
                    "message": "API endpoint discontinued",
                    "http_status": r.status_code,
                    "url": url,
                }

            if isinstance(js, dict):
                return True, {
                    "ok": True,
                    "http_status": r.status_code,
                    "url": url,
                    "status": js.get("status"),
                    "error_code": (js.get("error") or {}).get("code") if isinstance(js.get("error"), dict) else None,
                    "deprecated": bool(js.get("deprecated")) if isinstance(js, dict) else False,
                }

            return False, {
                "ok": False,
                "kind": "bad_payload",
                "code": "BAD_PAYLOAD",
                "message": "Non-JSON or invalid JSON response",
                "http_status": r.status_code,
                "url": url,
            }

        except requests.exceptions.Timeout:
            return False, {"ok": False, "kind": "timeout", "code": "TIMEOUT", "message": "timeout", "url": url}
        except requests.exceptions.RequestException as e:
            return False, {"ok": False, "kind": "network", "code": "NETWORK_ERROR", "message": str(e), "url": url}
        except Exception as e:
            return False, {"ok": False, "kind": "unknown", "code": "EXCEPTION", "message": str(e), "url": url}

    def _status_color_from_days(days_left: int | None) -> tuple[str, str]:
        # reprend ton monolithe : PREMIUM_GREEN_DAYS=14 / PREMIUM_YELLOW_DAYS=7
        green_days = int(getattr(s, "premium_green_days", 14) or 14)
        yellow_days = int(getattr(s, "premium_yellow_days", 7) or 7)

        if days_left is None:
            return "gray", "inconnu"
        if days_left >= green_days:
            return "green", f"{days_left}j"
        if yellow_days <= days_left < green_days:
            return "yellow", f"{days_left}j"
        return "red", f"{days_left}j"

    def synology_ping_safe(timeout: int = 6) -> dict:
        """
        Ping minimal DSM : login puis logout (pas de side effect).
        Dépend de send_to_download_station_safe pour la vraie fonction NAS, ici on fait du DSM direct comme le monolithe.
        """
        if not s.nas_enabled:
            return {"enabled": False, "ok": None, "message": "NAS disabled"}

        base = str(getattr(s, "synology_url", "") or "").strip().rstrip("/")
        if not base:
            return {"enabled": True, "ok": False, "message": "SYNOLOGY_URL missing"}

        login_url = f"{base}/webapi/auth.cgi"
        logout_url = f"{base}/webapi/auth.cgi"

        http = requests.Session()
        sid = None
        try:
            r = http.post(
                login_url,
                data={
                    "api": "SYNO.API.Auth",
                    "version": "3",
                    "method": "login",
                    "account": getattr(s, "synology_user", "") or "",
                    "passwd": getattr(s, "synology_password", "") or "",
                    "session": "DownloadStation",
                    "format": "sid",
                },
                timeout=timeout,
            )
            r.raise_for_status()
            js = r.json()
            if not js.get("success"):
                code = (js.get("error") or {}).get("code")
                return {"enabled": True, "ok": False, "message": f"DSM login failed (code={code})"}

            sid = (js.get("data") or {}).get("sid")
            if not sid:
                return {"enabled": True, "ok": False, "message": "DSM login ok but SID missing"}

            return {"enabled": True, "ok": True, "message": "DSM OK"}

        except requests.exceptions.Timeout:
            return {"enabled": True, "ok": False, "message": "DSM timeout"}
        except Exception as e:
            return {"enabled": True, "ok": False, "message": str(e)}
        finally:
            if sid:
                try:
                    http.post(
                        logout_url,
                        data={
                            "api": "SYNO.API.Auth",
                            "version": "3",
                            "method": "logout",
                            "session": "DownloadStation",
                            "_sid": sid,
                        },
                        timeout=timeout,
                    )
                except Exception:
                    pass
            try:
                http.close()
            except Exception:
                pass
    # -------------------------
    # UI routes
    # -------------------------
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
                    created, err, _st = process_one_item_public(line)
                    if created:
                        kind = created.get("kind", "item")
                        name = created.get("name") or line
                        extra = ""
                        if kind == "direct" and created.get("link"):
                            extra = " (lien prêt)"
                        flash(f"OK [{kind}] : {name}{extra}", "success")
                    else:
                        err = err or {"code": "UNKNOWN", "message": "Erreur inconnue"}
                        flash(f"Erreur : {err.get('code','UNKNOWN')} - {err.get('message','')}", "warning")
                except Exception as e:
                    logger.error("[PUBLIC] Erreur traitement ligne %s: %s", line, str(e), exc_info=True)
                    flash("Erreur interne (voir logs).", "warning")

            return redirect(url_for("index"))

        return render_template("index.html", **build_index_context(is_admin=False))

    @app.route("/admin", methods=["GET", "POST"])
    @require_admin
    def admin():
        # dans le monolithe: ADMIN_UI_ENABLED = True and NAS_ENABLED
        # Ici: on colle à ça => UI admin seulement si NAS actif.
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

            processor = process_one_item_admin if should_send else process_one_item_public

            if should_send:
                flash("Envoi NAS demandé : direct = envoi immédiat, magnet = planifié (scheduler).", "info")

            for line in lines:
                try:
                    created, err, _st = processor(line)
                    if created:
                        kind = created.get("kind", "item")
                        name = created.get("name") or line
                        extra = ""
                        if kind == "direct" and created.get("link"):
                            extra = " (lien prêt)"
                        if created.get("nas") == "sent":
                            extra = " (NAS envoyé)"
                        if created.get("nas") == "scheduled":
                            extra = " (NAS planifié)"
                        flash(f"OK [{kind}] : {name}{extra}", "success")
                    else:
                        err = err or {"code": "UNKNOWN", "message": "Erreur inconnue"}
                        flash(f"Erreur : {err.get('code','UNKNOWN')} - {err.get('message','')}", "warning")
                except Exception as e:
                    logger.error("[ADMIN] Erreur traitement ligne %s: %s", line, str(e), exc_info=True)
                    flash("Erreur interne (voir logs).", "warning")

            return redirect(url_for("admin"))

        return render_template("index.html", **build_index_context(is_admin=True))


    @app.route("/status", methods=["GET"])
    @require_admin
    def status_page():
        if not bool(getattr(s, "status_route_enabled", True)):
            abort(404)

        # timeouts (reprend monolithe: STATUS_HTTP_TIMEOUT=6, STATUS_DSM_TIMEOUT=6)
        http_timeout = int(getattr(s, "status_http_timeout", 6) or 6)
        dsm_timeout = int(getattr(s, "status_dsm_timeout", 6) or 6)

        # ping path (reprend AD_PING_PATH = env("ALLDEBRID_API_PING", "/v4/ping"))
        ad_ping_path = str(getattr(s, "ad_ping_path", "/v4/ping") or "/v4/ping")

        # 1) AllDebrid ping
        ad_ping_ok, ad_ping = _ad_request("GET", ad_ping_path, data=None, timeout=http_timeout)

        # 2) Tests endpoints "safe"
        endpoint_tests = [
            ("user", "GET", s.ad_endpoints["user"], None),
            ("magnet_status", "POST", s.ad_endpoints["magnet_status"], {"id[]": [0]}),
            ("magnet_files", "POST", s.ad_endpoints["magnet_files"], {"id[]": [0]}),
            ("link_unlock", "POST", s.ad_endpoints["link_unlock"], {"link": "http://example.invalid"}),
        ]

        ad_endpoints = []
        endpoints_discontinued = False
        endpoints_timeout_or_network = False

        for name, method, path, payload in endpoint_tests:
            ok, info = _ad_request(method, path, data=payload, timeout=http_timeout)

            state = "ok"
            color = "green"

            if not ok:
                code = info.get("code")
                if code == "DISCONTINUED":
                    state = "discontinued"
                    color = "red"
                    endpoints_discontinued = True
                else:
                    state = info.get("kind") or "error"
                    color = "yellow"
                    endpoints_timeout_or_network = True

            if ok and info.get("deprecated"):
                state = "deprecated"
                color = "yellow"

            ad_endpoints.append(
                {
                    "name": name,
                    "method": method,
                    "path": path,
                    "color": color,
                    "state": state,
                    "http_status": info.get("http_status"),
                    "error_code": info.get("error_code"),
                }
            )

        # 3) Premium info (cached)
        premium = get_premium_info_cached(s, rdb, ttl_seconds=300)
        days_left = None
        premium_until_ts = premium.get("premium_until_ts")
        if premium_until_ts:
            try:
                now_ts = int(time.time())
                days_left = max(-9999, int((int(premium_until_ts) - now_ts) / 86400))
            except Exception:
                days_left = None

        premium_color, premium_label = _status_color_from_days(days_left)
        premium_ok = bool(premium.get("ok"))

        # 4) Redis ping
        redis_info = {"ok": False, "message": "unknown"}
        try:
            pong = rdb.ping()
            redis_info = {"ok": bool(pong), "message": "OK" if pong else "PING failed"}
        except Exception as e:
            redis_info = {"ok": False, "message": str(e)}

        # 5) NAS ping
        nas_info = synology_ping_safe(timeout=dsm_timeout)

        # 6) Overall
        overall = "green"
        if endpoints_discontinued:
            overall = "red"
        elif (not ad_ping_ok) or endpoints_timeout_or_network or (not redis_info["ok"]) or (nas_info.get("enabled") and not nas_info.get("ok")) or (not premium_ok):
            overall = "yellow"

        return render_template(
            "status.html",
            now=datetime.now(),
            overall=overall,
            ad_ping_ok=ad_ping_ok,
            ad_ping=ad_ping,
            ad_endpoints=ad_endpoints,
            premium=premium,
            premium_days_left=days_left,
            premium_color=premium_color,
            premium_label=premium_label,
            redis_info=redis_info,
            nas_info=nas_info,
            NAS_ENABLED=bool(s.nas_enabled),
        )


    # -------------------------
    # API routes
    # -------------------------
    @app.route("/api/capabilities", methods=["GET"])
    def api_capabilities():
        return jsonify(
            {"success": True, "version": s.app_version, "capabilities": {"nas_enabled": bool(s.nas_enabled)}}
        )

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
            c, e, st = process_one_item_public(it)
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
                            mk_error("", {"kind": "forbidden", "code": rs.NAS_ERROR_NAS_DISABLED, "message": "NAS feature is disabled."})
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
            c, e, st = process_one_item_admin(it)
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

            # pending = pas de liens prêts
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

            # completed = liens prêts
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

        http_timeout = int(getattr(s, "status_http_timeout", 6) or 6)
        dsm_timeout = int(getattr(s, "status_dsm_timeout", 6) or 6)
        ad_ping_path = str(getattr(s, "ad_ping_path", "/v4/ping") or "/v4/ping")

        # 1) AllDebrid ping
        ad_ping_ok, ad_ping = _ad_request("GET", ad_ping_path, data=None, timeout=http_timeout)

        # 2) Endpoints tests
        endpoint_tests = [
            ("user", "GET", s.ad_endpoints["user"], None),
            ("magnet_status", "POST", s.ad_endpoints["magnet_status"], {"id[]": [0]}),
            ("magnet_files", "POST", s.ad_endpoints["magnet_files"], {"id[]": [0]}),
            ("link_unlock", "POST", s.ad_endpoints["link_unlock"], {"link": "http://example.invalid"}),
        ]

        ad_endpoints = []
        endpoints_discontinued = False
        endpoints_timeout_or_network = False

        for name, method, path, payload in endpoint_tests:
            ok, info = _ad_request(method, path, data=payload, timeout=http_timeout)

            state = "ok"
            color = "green"

            if not ok:
                code = info.get("code")
                if code == "DISCONTINUED":
                    state = "discontinued"
                    color = "red"
                    endpoints_discontinued = True
                else:
                    state = info.get("kind") or "error"
                    color = "yellow"
                    endpoints_timeout_or_network = True

            if ok and info.get("deprecated"):
                state = "deprecated"
                color = "yellow"

            ad_endpoints.append(
                {
                    "name": name,
                    "method": method,
                    "path": path,
                    "color": color,
                    "state": state,
                    "http_status": info.get("http_status"),
                    "error_code": info.get("error_code"),
                }
            )

        # 3) Premium info (cached)
        premium = get_premium_info_cached(s, rdb, ttl_seconds=300)
        days_left = None
        premium_until_ts = premium.get("premium_until_ts")
        if premium_until_ts:
            try:
                now_ts = int(time.time())
                days_left = max(-9999, int((int(premium_until_ts) - now_ts) / 86400))
            except Exception:
                days_left = None

        premium_color, premium_label = _status_color_from_days(days_left)
        premium_ok = bool(premium.get("ok"))

        # 4) Redis ping
        redis_info = {"ok": False, "message": "unknown"}
        try:
            pong = rdb.ping()
            redis_info = {"ok": bool(pong), "message": "OK" if pong else "PING failed"}
        except Exception as e:
            redis_info = {"ok": False, "message": str(e)}

        # 5) NAS ping
        nas_info = synology_ping_safe(timeout=dsm_timeout)

        # 6) Overall
        overall = "green"
        if endpoints_discontinued:
            overall = "red"
        elif (not ad_ping_ok) or endpoints_timeout_or_network or (not redis_info["ok"]) or (nas_info.get("enabled") and not nas_info.get("ok")) or (not premium_ok):
            overall = "yellow"

        return jsonify(
            {
                "now": datetime.now().isoformat(),
                "overall": overall,
                "ad_ping_ok": ad_ping_ok,
                "ad_ping": ad_ping,
                "ad_endpoints": ad_endpoints,
                "premium": premium,
                "premium_days_left": days_left,
                "premium_color": premium_color,
                "premium_label": premium_label,
                "redis_info": redis_info,
                "nas_info": nas_info,
                "nas_enabled": bool(s.nas_enabled),
            }
        )


    # -------------------------
    # Admin tools routes
    # -------------------------
    @app.route("/debug_redis", methods=["GET"])
    @require_admin
    def debug_redis():
        try:
            keys = rs.iter_all_items_keys(rdb)
            debug_info = []
            for k in keys:
                key_str = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)
                data = rdb.hgetall(k)
                decoded_data = rs.decode_hash(data)
                debug_info.append({"key": key_str, "data": decoded_data})
            return render_template("debug_redis.html", torrents=debug_info)
        except Exception as e:
            logger.error("Erreur debug_redis: %s", str(e), exc_info=True)
            return f"Erreur: {str(e)}", 500

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

            if not found_key:
                return jsonify({"success": False, "error": "Item non trouvé"}), 404

            app_status_b = rdb.hget(found_key, "app_status")
            app_status = (app_status_b or b"").decode("utf-8", "ignore").strip()
            if app_status == rs.APP_STATUS_NAS_SENT:
                return jsonify({"success": True, "message": "Déjà envoyé au NAS."})

            # magnet => planifier
            if found_kind == "magnet":
                rdb.hset(
                    found_key,
                    mapping={"app_status": rs.APP_STATUS_NAS_PENDING, "nas_requested_at": str(time.time()), "nas_error": ""},
                )
                return jsonify({"success": True, "message": "Envoi au NAS planifié (scheduler)."})

            # direct => envoyer maintenant
            data = rdb.hgetall(found_key)
            decoded = rs.decode_hash(data)
            links = rs.parse_links_dicts(decoded)
            urls = [x.get("link") for x in links if isinstance(x, dict) and str(x.get("link") or "").strip()]

            if not urls:
                rdb.hset(
                    found_key,
                    mapping={
                        "app_status": rs.APP_STATUS_NAS_FAILED,
                        "sent_to_nas": "false",
                        "nas_error": rs.NAS_ERROR_NO_LINKS,
                        "nas_last_attempt": str(time.time()),
                    },
                )
                return jsonify({"success": False, "error": "Aucun lien à envoyer"}), 422

            if not s.nas_enabled:
                rdb.hset(
                    found_key,
                    mapping={
                        "app_status": rs.APP_STATUS_NAS_DISABLED,
                        "sent_to_nas": "false",
                        "nas_error": rs.NAS_ERROR_NAS_DISABLED,
                        "nas_last_attempt": str(time.time()),
                    },
                )
                return jsonify({"success": False, "error": rs.NAS_ERROR_NAS_DISABLED}), 403

            lock_id = found_key  # lock par clé complète (comme tes conventions)
            if not rs.acquire_nas_send_lock(rdb, lock_id, ttl_seconds=900):
                return jsonify({"success": True, "message": "Envoi déjà en cours."})

            try:
                ok_send, send_err = send_to_download_station_safe(s, urls)

                if ok_send:
                    rdb.hset(
                        found_key,
                        mapping={
                            "app_status": rs.APP_STATUS_NAS_SENT,
                            "sent_to_nas": "true",
                            "sent_to_nas_at": str(time.time()),
                            "nas_error": "",
                            "nas_last_attempt": str(time.time()),
                        },
                    )
                    return jsonify({"success": True, "message": f"{len(urls)} lien(s) envoyé(s) au NAS."})

                code = (send_err or {}).get("code") or "NAS_SEND_FAILED"
                msg = (send_err or {}).get("message") or "send_failed"
                rdb.hset(
                    found_key,
                    mapping={
                        "app_status": rs.APP_STATUS_NAS_FAILED,
                        "sent_to_nas": "false",
                        "nas_error": f"{code}: {msg}",
                        "nas_last_attempt": str(time.time()),
                    },
                )
                return jsonify({"success": False, "error": f"{code}: {msg}"}), 502

            finally:
                rs.release_nas_send_lock(rdb, lock_id)

        except Exception as e:
            logger.error("Erreur send_to_nas: %s", str(e), exc_info=True)
            return jsonify({"success": False, "error": f"Erreur: {str(e)}"}), 500

    @app.route("/delete_torrent/<torrent_id>", methods=["POST"])
    def delete_torrent(torrent_id: str):
        """
        Accepte ids préfixés OU non.
        - "magnet:123" / "direct:abc"
        - "123" => tente magnet:123 puis direct:123
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
            found_data = {}

            for key_str in candidates:
                if rdb.exists(key_str):
                    found_key = key_str
                    found_kind, found_id = rs.redis_key_id(key_str)
                    found_data = rs.decode_hash(rdb.hgetall(key_str))
                    break

            if not found_key:
                return jsonify({"success": False, "error": "Item non trouvé"}), 404

            item_name = (found_data.get("name") or "inconnu").strip() or "inconnu"

            # tombstone
            rs.mark_deleted(rdb, found_key, item_name, found_kind)
            logger.info("[DELETE] tombstone set key=%s name=%s kind=%s", found_key, item_name, found_kind)

            # delete côté AllDebrid seulement pour magnets
            if found_kind == "magnet":
                ad_url = f"{s.alldebrid_base_url}{s.ad_endpoints['magnet_delete']}"
                headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}
                try:
                    r = requests.post(ad_url, data={"id": found_id}, headers=headers, timeout=s.alldebrid_timeout)
                    js = None
                    try:
                        js = r.json()
                    except Exception:
                        js = None
                    if (not r.ok) or (isinstance(js, dict) and js.get("status") != "success"):
                        logger.warning("[DELETE] AllDebrid delete failed magnet id=%s http=%s", found_id, r.status_code)
                    else:
                        logger.info("[DELETE] AllDebrid deleted magnet id=%s", found_id)
                except Exception as e:
                    logger.warning("[DELETE] AllDebrid delete error magnet id=%s: %s", found_id, str(e))

            # cleanup Redis + locks
            try:
                rdb.delete(found_key)
            except Exception:
                pass

            # lock: nouveau (clé complète) + compat (id nu)
            try:
                rdb.delete(f"nas_send_lock:{found_key}")
            except Exception:
                pass
            try:
                rdb.delete(f"nas_send_lock:{found_id}")
            except Exception:
                pass

            logger.info("[DELETE] Redis deleted key=%s name=%s", found_key, item_name)
            return jsonify({"success": True, "message": f"Item {item_name} supprimé avec succès"})

        except Exception as e:
            logger.error("[DELETE] route error id=%s: %s", torrent_id, str(e), exc_info=True)
            return jsonify({"success": False, "error": f"Erreur: {str(e)}"}), 500

    @app.route("/delete_all_completed", methods=["POST"])
    def delete_all_completed():
        """
        Supprime tous les items "completed" (status ready/completed + links_count>0)
        - delete côté AD pour magnets
        - delete Redis (item + nas_send_lock)
        """
        try:
            keys = rs.iter_all_items_keys(rdb)
            if not keys:
                return jsonify({"success": True, "deleted": 0, "failed": 0, "details": []})

            pipe = rdb.pipeline()
            for k in keys:
                pipe.hget(k, "status")
                pipe.hget(k, "links_count")
                pipe.hget(k, "type")
                pipe.hget(k, "name")
            vals = pipe.execute()

            to_delete_keys = []
            meta_by_key = {}

            for i, k in enumerate(keys):
                base = i * 4
                status = (vals[base] or b"").decode("utf-8", "ignore").lower().strip()
                links_count_s = (vals[base + 1] or b"0").decode("utf-8", "ignore").strip()
                t_type = (vals[base + 2] or b"").decode("utf-8", "ignore").strip().lower()
                name = (vals[base + 3] or b"").decode("utf-8", "ignore").strip() or "inconnu"

                try:
                    links_count = int(links_count_s or "0")
                except Exception:
                    links_count = 0

                is_completed = (status in {"ready", "completed"}) and (links_count > 0)
                if is_completed:
                    to_delete_keys.append(k)
                    meta_by_key[k] = {"type": t_type, "name": name}

            if not to_delete_keys:
                return jsonify({"success": True, "deleted": 0, "failed": 0, "details": []})

            deleted = 0
            failed = 0
            details = []

            ad_url = f"{s.alldebrid_base_url}{s.ad_endpoints['magnet_delete']}"
            headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}

            http = requests.Session()
            del_pipe = rdb.pipeline()

            for k in to_delete_keys:
                try:
                    key_str = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)
                    kind, item_id = rs.redis_key_id(key_str)

                    t_name = meta_by_key.get(k, {}).get("name") or "inconnu"
                    t_type = meta_by_key.get(k, {}).get("type") or kind

                    ad_ok = True
                    ad_err = None

                    if kind == "magnet" or t_type == "magnet":
                        try:
                            r = http.post(ad_url, data={"id": item_id}, headers=headers, timeout=s.alldebrid_timeout)
                            js = None
                            try:
                                js = r.json()
                            except Exception:
                                js = None
                            if (not r.ok) or (isinstance(js, dict) and js.get("status") != "success"):
                                ad_ok = False
                                ad_err = {"kind": "http_error", "code": f"HTTP_{r.status_code}", "message": "delete failed"}
                        except Exception as e:
                            ad_ok = False
                            ad_err = {"kind": "unknown", "code": "EXCEPTION", "message": str(e)}

                    del_pipe.delete(k)
                    del_pipe.delete(f"nas_send_lock:{key_str}")  # clé complète
                    del_pipe.delete(f"nas_send_lock:{item_id}")  # compat id nu

                    deleted += 1
                    details.append(
                        {
                            "id": item_id,
                            "kind": kind,
                            "name": t_name,
                            "alldebrid_deleted": ad_ok,
                            "alldebrid_error": ad_err,
                        }
                    )

                except Exception as e:
                    failed += 1
                    logger.error("Erreur suppression bulk sur %s: %s", str(k), str(e), exc_info=True)
                    details.append(
                        {"id": None, "kind": None, "name": None, "alldebrid_deleted": False, "alldebrid_error": str(e)}
                    )

            del_pipe.execute()
            try:
                http.close()
            except Exception:
                pass

            return jsonify({"success": True, "deleted": deleted, "failed": failed, "details": details})

        except Exception as e:
            logger.error("Erreur suppression bulk: %s", str(e), exc_info=True)
            return jsonify({"success": False, "error": f"Erreur: {str(e)}"}), 500

    return app