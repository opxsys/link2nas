# link2nas/web_admin_tools.py
from __future__ import annotations

import logging
import time
from typing import Any

import redis
import requests
from flask import jsonify
from flask import current_app

from . import redis_store as rs
from .config import Settings
from .web_helpers import redact_url, scrub_for_log


def register_admin_tools_routes(app, s: Settings, rdb: redis.Redis, logger: logging.Logger, require_admin):
    """
    Register admin tools routes on a Flask app.

    Why a registrar instead of defining routes in webapp.py?
    - keeps webapp.py readable
    - isolates admin-only, side-effect routes (delete/sends/bulk ops)
    - makes it easy to disable/extend tools without touching core routes
    """

    # ============================================================
    # Delete single item (magnet/direct)
    # ============================================================

    @app.route("/delete_torrent/<torrent_id>", methods=["POST"])
#    @require_admin
    def delete_torrent(torrent_id: str):
        """
        Accepts ids prefixed or not:
          - "magnet:123" / "direct:abc"
          - "123" => tries magnet:123 then direct:123

        Behavior:
        - mark tombstone (so UI can reflect deletion intent if you keep records)
        - best-effort delete in AllDebrid for magnets
        - delete Redis item and its lock keys
        """
        try:
            tid = (torrent_id or "").strip()
            if tid.startswith("magnet:") or tid.startswith("direct:"):
                candidates = [tid]
            else:
                candidates = [f"magnet:{tid}", f"direct:{tid}"]

            found_key: str | None = None
            found_kind: str | None = None
            found_id: str | None = None
            found_data: dict[str, str] = {}

            for key_str in candidates:
                if rdb.exists(key_str):
                    found_key = key_str
                    found_kind, found_id = rs.redis_key_id(key_str)
                    found_data = rs.decode_hash(rdb.hgetall(key_str))
                    break

            if not found_key:
                return jsonify({"success": False, "error": "Item non trouvé"}), 404

            item_name = (found_data.get("name") or "inconnu").strip() or "inconnu"

            # Tombstone first (best-effort)
            rs.mark_deleted(rdb, found_key, item_name, found_kind or "unknown")
            logger.info("[DELETE] tombstone set key=%s name=%s kind=%s", found_key, item_name, found_kind)

            # AllDebrid delete (magnets only) - best-effort, no hard fail
            if (found_kind == "magnet") and found_id:
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
                        logger.warning(
                            "[DELETE] AllDebrid delete failed magnet id=%s http=%s body=%s",
                            found_id,
                            r.status_code,
                            scrub_for_log(js) if isinstance(js, dict) else "(non-json)",
                        )
                    else:
                        logger.info("[DELETE] AllDebrid deleted magnet id=%s", found_id)

                except Exception as e:
                    logger.warning("[DELETE] AllDebrid delete error magnet id=%s: %s", found_id, str(e))

            # Redis delete item + locks
            try:
                rdb.delete(found_key)
            except Exception:
                pass

            try:
                rdb.delete(f"nas_send_lock:{found_key}")
            except Exception:
                pass

            # Optional: lock by id (legacy)
            if found_id:
                try:
                    rdb.delete(f"nas_send_lock:{found_id}")
                except Exception:
                    pass

            logger.info("[DELETE] Redis deleted key=%s name=%s", found_key, item_name)
            return jsonify({"success": True, "message": f"Item {item_name} supprimé avec succès"})

        except Exception as e:
            logger.error("[DELETE] route error id=%s: %s", redact_url(torrent_id), str(e), exc_info=True)
            return jsonify({"success": False, "error": f"Erreur: {str(e)}"}), 500

    # ============================================================
    # Delete all completed items
    # ============================================================

    @app.route("/delete_all_completed", methods=["POST"])
#    @require_admin
    def delete_all_completed():
        """
        Deletes all items considered "completed":
        - status in {"ready","completed"} AND links_count > 0

        For each item:
        - if magnet: best-effort delete in AllDebrid
        - delete Redis item
        - delete lock keys (nas_send_lock:<redis_key> + nas_send_lock:<id>)

        Returns:
          {success, deleted, failed, details[]}
        """
        try:
            keys = rs.iter_all_items_keys(rdb)
            if not keys:
                return jsonify({"success": True, "deleted": 0, "failed": 0, "details": []})

            # Pipeline fetch minimal fields needed to decide + annotate response.
            pipe = rdb.pipeline()
            for k in keys:
                pipe.hget(k, "status")
                pipe.hget(k, "links_count")
                pipe.hget(k, "type")
                pipe.hget(k, "name")
            vals = pipe.execute()

            to_delete_keys: list[bytes] = []
            meta_by_key: dict[bytes, dict[str, str]] = {}

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

            ad_url = f"{s.alldebrid_base_url}{s.ad_endpoints['magnet_delete']}"
            headers = {"Authorization": f"Bearer {s.alldebrid_apikey}"}

            deleted = 0
            failed = 0
            details: list[dict[str, Any]] = []

            http = requests.Session()
            del_pipe = rdb.pipeline()

            for k in to_delete_keys:
                try:
                    key_str = k.decode("utf-8") if isinstance(k, (bytes, bytearray)) else str(k)
                    kind, item_id = rs.redis_key_id(key_str)

                    t_name = meta_by_key.get(k, {}).get("name") or "inconnu"
                    t_type = meta_by_key.get(k, {}).get("type") or kind

                    ad_ok = True
                    ad_err: dict[str, Any] | None = None

                    # AllDebrid delete is only meaningful for magnets
                    if (kind == "magnet") or (t_type == "magnet"):
                        try:
                            r = http.post(ad_url, data={"id": item_id}, headers=headers, timeout=s.alldebrid_timeout)

                            js = None
                            try:
                                js = r.json()
                            except Exception:
                                js = None

                            if (not r.ok) or (isinstance(js, dict) and js.get("status") != "success"):
                                ad_ok = False
                                ad_err = {
                                    "kind": "http_error",
                                    "code": f"HTTP_{r.status_code}",
                                    "message": "delete failed",
                                }

                        except Exception as e:
                            ad_ok = False
                            ad_err = {"kind": "unknown", "code": "EXCEPTION", "message": str(e)}

                    # Queue deletes (redis item + locks)
                    del_pipe.delete(k)
                    del_pipe.delete(f"nas_send_lock:{key_str}")
                    del_pipe.delete(f"nas_send_lock:{item_id}")

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
                    logger.error("Erreur suppression bulk sur %s: %s", redact_url(str(k)), str(e), exc_info=True)
                    details.append(
                        {
                            "id": None,
                            "kind": None,
                            "name": None,
                            "alldebrid_deleted": False,
                            "alldebrid_error": {"kind": "exception", "code": "EXCEPTION", "message": str(e)},
                        }
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
