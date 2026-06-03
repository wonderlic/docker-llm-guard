#!/bin/bash
set -e

APP_WORKERS=${APP_WORKERS:-1}
APP_PORT=${APP_PORT:-8000}

exec uvicorn --factory api.app:create_app \
  --host=0.0.0.0 \
  --port="$APP_PORT" \
  --workers="$APP_WORKERS" \
  --forwarded-allow-ips="*" \
  --proxy-headers \
  --timeout-keep-alive="2"
