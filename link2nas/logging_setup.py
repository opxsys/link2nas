# link2nas/logging_setup.py
from __future__ import annotations

import logging
import os
import sys


# ==============================================================================
# Logging bootstrap
#
# Rôle :
# - Initialiser UNE configuration logging globale et prévisible
# - Compatible CLI / systemd / gunicorn
# - Centralise le niveau de log via variables d’environnement
#
# Convention :
# - LOG_LEVEL  : niveau principal du projet (DEBUG/INFO/WARNING/ERROR)
# - LOGLEVEL   : alias de compatibilité (outils externes)
# - LOG_FORCE  : force la réinitialisation des handlers existants
#
# ⚠️ LOG_FORCE doit rester à 0 en production normale
# ==============================================================================


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse une variable d’environnement booléenne."""
    v = str(os.getenv(name, "")).strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _resolve_log_level() -> int:
    """
    Détermine le niveau de log effectif.
    Priorité :
      1) LOG_LEVEL (projet)
      2) LOGLEVEL  (compatibilité)
      3) INFO
    """
    level_name = (os.getenv("LOG_LEVEL") or os.getenv("LOGLEVEL") or "INFO").upper().strip()
    return getattr(logging, level_name, logging.INFO)


def setup_logging() -> logging.Logger:
    """
    Initialise le logging global de l’application.

    À appeler **une seule fois**, le plus tôt possible
    (ex: scheduler_runner.py, entrypoint WSGI).

    Retourne le logger racine du projet : `link2nas`.
    """
    level = _resolve_log_level()
    force = _env_bool("LOG_FORCE", False)

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
        force=force,
    )

    # Logger racine du projet
    root_logger = logging.getLogger("link2nas")
    root_logger.setLevel(level)

    return root_logger
