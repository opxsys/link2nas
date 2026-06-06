# Stage 1: Build frontend-next
FROM node:20-slim AS frontend-next-builder
WORKDIR /build
COPY frontend-next/package.json frontend-next/package-lock.json ./
RUN npm ci
COPY frontend-next/ ./
RUN npm run build

# Stage 2: Python application
FROM python:3.13-slim

ARG APP_VERSION=unknown
ENV APP_VERSION=${APP_VERSION}

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r /app/requirements.txt

COPY . /app

# Overlay the freshly built frontend-next dist (overrides anything from COPY . /app)
COPY --from=frontend-next-builder /build/dist /app/frontend-next/dist

RUN mkdir -p /app/data /app/downloads /app/tmp /app/logs

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:create_app()"]
