# scheduler_runner.py
from __future__ import annotations

import logging
import time
import os,sys
import redis
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

from link2nas.config import load_settings
from link2nas.scheduler_jobs import check_pending_torrents

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("link2nas.scheduler_runner")


def main():
    s = load_settings()

    if not s.scheduler_enabled:
        val = os.getenv("SCHEDULER_ENABLED", "")
        logger.warning("Scheduler disabled (SCHEDULER_ENABLED=%r)", val)        
        return

    rdb = redis.Redis(host=s.redis_host, port=s.redis_port, db=s.redis_db)

    sched = BackgroundScheduler()
    sched.add_job(
        lambda: check_pending_torrents(s, rdb),
        "interval",
        seconds=s.scheduler_interval_seconds,
        max_instances=s.scheduler_max_instances,
        coalesce=s.scheduler_coalesce,
        misfire_grace_time=s.scheduler_misfire_grace_seconds,
    )
    sched.start()

    logger.info("Scheduler started")

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        sched.shutdown()
        logger.warning("Scheduler stopped")


if __name__ == "__main__":
    main()
