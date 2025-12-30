from __future__ import annotations

import logging
from . import config


def setup_logging() -> logging.Logger:
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return logging.getLogger("link2nas")
