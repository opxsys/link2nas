from __future__ import annotations

import os

from link2nas.config import load_settings
from link2nas.webapp import create_app

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

s = load_settings()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # /opt/link2nas
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = create_app(s, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)