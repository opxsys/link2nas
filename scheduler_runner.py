# link2nas/scheduler_runner.py
from __future__ import annotations

"""
Scheduler process entrypoint.

Role
- Runs APScheduler in a dedicated process/container.
- Periodically calls scheduler_jobs.check_pending_torrents().

Notes
- This module must be "boring": minimal logic, no business rules here.
- Business rules live in:
    - link2nas/scheduler_jobs.py (what to do each tick)
    - link2nas/nas_send.py (how to send)
    - link2nas/alldebrid.py (how to query AllDebrid)
"""

import logging
import os
import signal
import time
from typing import Optional

import redis
from apscheduler.schedulers.background import BackgroundScheduler

from link2nas.config import load_settings
from link2nas.logging_setup import setup_logging
from link2nas.scheduler_jobs import check_pending_torrents

# Ensure logging is configured as early as possible.
setup_logging()

logger = logging.getLogger("link2nas.scheduler_runner")


def _env_raw(name: str) -> str:
    """Read an env var as raw string for diagnostics/logging."""
    return str(os.getenv(name, "") or "").strip()


def _build_redis(s) -> redis.Redis:
    """Create Redis client for scheduler process."""
    return redis.Redis(host=s.redis_host, port=s.redis_port, db=s.redis_db)


def _install_signal_handlers(sched: BackgroundScheduler) -> None:
    """
    Graceful shutdown on SIGTERM/SIGINT.
    - SIGTERM is common in Docker/K8s stops.
    - SIGINT is common when running locally.
    """
    def _stop(_signum, _frame):  # noqa: ANN001
        try:
            logger.warning("[SCHED] stop signal received, shutting down...")
            sched.shutdown(wait=True)
        except Exception:
            logger.exception("[SCHED] shutdown error")
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)


def main() -> int:
    """
    Start scheduler loop.
    Returns process exit code.
    """
    s = load_settings()

    # Hard gate: if scheduler disabled, exit cleanly.
    if not s.scheduler_enabled:
        logger.warning("[SCHED] disabled (SCHEDULER_ENABLED=%r)", _env_raw("SCHEDULER_ENABLED"))
        return 0

    rdb = _build_redis(s)

    # Optional: fail-fast if Redis not reachable at startup.
    # (If you prefer "best-effort", remove this ping.)
    try:
        rdb.ping()
    except Exception as e:
        logger.error("[SCHED] redis not reachable: %s", str(e))
        return 2

    sched = BackgroundScheduler()

    # Single periodic job: all logic is in check_pending_torrents().
    # APScheduler settings are controlled by env/config (see Settings).
    sched.add_job(
        func=lambda: check_pending_torrents(s, rdb),
        trigger="interval",
        seconds=int(s.scheduler_interval_seconds),
        max_instances=int(s.scheduler_max_instances),
        coalesce=bool(s.scheduler_coalesce),
        misfire_grace_time=int(s.scheduler_misfire_grace_seconds),
        id="check_pending_torrents",
        replace_existing=True,
    )

    _install_signal_handlers(sched)

    sched.start()
    logger.info(
        "[SCHED] started interval=%ss max_instances=%s coalesce=%s misfire_grace=%ss",
        s.scheduler_interval_seconds,
        s.scheduler_max_instances,
        s.scheduler_coalesce,
        s.scheduler_misfire_grace_seconds,
    )

    # Keep the process alive.
    # BackgroundScheduler uses its own threads; this loop is just a "sleep forever".
    try:
        while True:
            time.sleep(3600)
    except SystemExit:
        # signal handler exits via SystemExit
        return 0
    except Exception:
        logger.exception("[SCHED] main loop crashed")
        return 3
    finally:
        try:
            sched.shutdown(wait=False)
        except Exception:
            pass
        logger.warning("[SCHED] stopped")


if __name__ == "__main__":
    raise SystemExit(main())