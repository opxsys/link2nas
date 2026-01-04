FROM python:3.11-slim

# Build-time version baked into the image
ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN adduser --disabled-password --gecos "" --uid 10001 appuser

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY scheduler_runner.py /app/scheduler_runner.py
COPY link2nas /app/link2nas

# Bake version module (prevents .env from overriding app version)
RUN python - <<'PY'
import os, pathlib
v = os.environ.get("APP_VERSION", "dev")
pathlib.Path("/app/link2nas/_version.py").write_text(f"__version__ = {v!r}\n")
print("Wrote /app/link2nas/_version.py:", v)
PY

COPY templates /app/templates
COPY static /app/static

RUN chown -R appuser:appuser /app

EXPOSE 5000
USER appuser

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:app"]