from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any


HEALTH_CHECK_PATH = "/health"
HEALTH_CHECK_EXCLUDED_URL = r".*/health(?:\?.*)?$"
OTEL_EXCLUDED_URLS_ENVS = (
    "OTEL_PYTHON_FASTAPI_EXCLUDED_URLS",
    "OTEL_PYTHON_EXCLUDED_URLS",
)


class HealthCheckAccessFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if record.name != "uvicorn.access":
            return True

        path = access_log_path(record.args)
        return path != HEALTH_CHECK_PATH


def access_log_path(args: object) -> str | None:
    if not isinstance(args, tuple) or len(args) < 3:
        return None

    path = args[2]
    if not isinstance(path, str):
        return None

    return path.split("?", 1)[0]


def exclude_health_check_tracing() -> None:
    for env_name in OTEL_EXCLUDED_URLS_ENVS:
        excluded_urls = [
            value.strip()
            for value in os.environ.get(env_name, "").split(",")
            if value.strip()
        ]
        if HEALTH_CHECK_EXCLUDED_URL not in excluded_urls:
            excluded_urls.append(HEALTH_CHECK_EXCLUDED_URL)
        os.environ[env_name] = ",".join(excluded_urls)


def is_health_check_span(span: Any) -> bool:
    if getattr(span, "name", "").upper().startswith("GET /HEALTH"):
        return True

    attributes = getattr(span, "attributes", None)
    if not isinstance(attributes, Mapping):
        return False

    for key in ("http.route", "http.target", "url.path"):
        value = attributes.get(key)
        if isinstance(value, str) and health_check_path(value):
            return True

    http_url = attributes.get("http.url") or attributes.get("url.full")
    return isinstance(http_url, str) and health_check_path(http_url)


def health_check_path(value: str) -> bool:
    return value.split("?", 1)[0].rstrip("/").endswith(HEALTH_CHECK_PATH)
