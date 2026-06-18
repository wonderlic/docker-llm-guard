from __future__ import annotations

import os
from urllib.parse import quote, urlparse


ARIZE_AX_API_VERSION = "arize-ax"
PHOENIX_API_VERSION = "phoenix"
ARIZE_AX_TRACING_ENDPOINT = "https://otlp.arize.com/v1/traces"
ARIZE_AX_TRACING_HOST = "otlp.arize.com"
PHOENIX_TRACING_ENDPOINT = "http://phoenix:6006/v1/traces"
OTEL_TRACES_HEADERS_ENV = "OTEL_EXPORTER_OTLP_TRACES_HEADERS"


def get_env_value(*names: str) -> str:
    for name in names:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()

    return ""


def get_phoenix_api_version() -> str:
    return get_env_value("PHOENIX_API_VERSION", "PHOENIX.API_VERSION").lower()


def get_tracing_endpoint(phoenix_api_version: str) -> str | None:
    phoenix_endpoint = get_env_value(
        "PHOENIX_TRACING_COLLECTOR_ENDPOINT",
        "PHOENIX.TRACING.COLLECTOR_ENDPOINT",
    )
    if phoenix_api_version == ARIZE_AX_API_VERSION:
        return phoenix_endpoint or ARIZE_AX_TRACING_ENDPOINT
    if phoenix_api_version == PHOENIX_API_VERSION:
        return phoenix_endpoint or get_env_value("TRACING_OTEL_ENDPOINT") or PHOENIX_TRACING_ENDPOINT

    return phoenix_endpoint or get_env_value("TRACING_OTEL_ENDPOINT") or None


def validate_tracing_endpoint(phoenix_api_version: str, endpoint: str | None) -> None:
    if phoenix_api_version == PHOENIX_API_VERSION and is_arize_ax_endpoint(endpoint):
        raise RuntimeError(
            "PHOENIX_API_VERSION=phoenix cannot export to https://otlp.arize.com. "
            "Set PHOENIX_API_VERSION=arize-ax and configure PHOENIX_SPACE_ID or "
            "PHOENIX_SPACE_KEY, or point TRACING_OTEL_ENDPOINT at a Phoenix endpoint."
        )


def is_arize_ax_endpoint(endpoint: str | None) -> bool:
    if not endpoint:
        return False

    return urlparse(endpoint).hostname == ARIZE_AX_TRACING_HOST


def configure_phoenix_tracing_headers(app_name: str) -> None:
    api_key = get_env_value("PHOENIX_API_KEY", "PHOENIX.API_KEY")
    project_name = get_phoenix_project_name(app_name)
    headers = parse_otel_headers(os.environ.get(OTEL_TRACES_HEADERS_ENV, ""))
    headers.pop("arize-space-id", None)
    headers.pop("arize-space-key", None)
    headers.pop("arize-api-key", None)

    if api_key:
        headers["authorization"] = f"Bearer%20{quote(api_key, safe='')}"
    headers.setdefault("x-project-name", project_name)
    os.environ[OTEL_TRACES_HEADERS_ENV] = serialize_otel_headers(headers)


def configure_arize_ax_tracing_headers() -> None:
    space_id = get_env_value("PHOENIX_SPACE_ID", "PHOENIX.SPACE_ID", "ARIZE_SPACE_ID")
    space_key = get_env_value("PHOENIX_SPACE_KEY", "PHOENIX.SPACE_KEY", "ARIZE_SPACE_KEY")
    api_key = get_env_value("PHOENIX_API_KEY", "PHOENIX.API_KEY", "ARIZE_API_KEY")
    if not space_id and not space_key:
        raise RuntimeError(
            "Arize AX tracing is enabled but neither PHOENIX_SPACE_ID nor PHOENIX_SPACE_KEY is configured"
        )
    if not api_key:
        raise RuntimeError("Arize AX tracing is enabled but PHOENIX_API_KEY is not configured")

    headers = parse_otel_headers(os.environ.get(OTEL_TRACES_HEADERS_ENV, ""))
    headers.pop("authorization", None)
    headers.pop("x-project-name", None)
    headers.pop("arize-space-id", None)
    headers.pop("arize-space-key", None)
    if space_id:
        headers["arize-space-id"] = quote(space_id, safe="")
    else:
        headers["arize-space-key"] = quote(space_key, safe="")
    headers["arize-api-key"] = quote(api_key, safe="")
    os.environ[OTEL_TRACES_HEADERS_ENV] = serialize_otel_headers(headers)


def get_phoenix_project_name(app_name: str) -> str:
    return get_env_value(
        "PHOENIX_TRACING_PROJECT_NAME",
        "PHOENIX.TRACING.PROJECT_NAME",
        "TRACING_PROJECT_NAME",
    ) or app_name


def get_arize_ax_project_name(app_name: str) -> str:
    return get_env_value(
        "PHOENIX_TRACING_PROJECT_NAME",
        "PHOENIX.TRACING.PROJECT_NAME",
        "ARIZE_PROJECT_NAME",
        "TRACING_PROJECT_NAME",
    ) or app_name


def parse_otel_headers(value: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for header in value.split(","):
        if "=" not in header:
            continue
        key, header_value = header.split("=", 1)
        key = key.strip()
        if key:
            headers[key.lower()] = header_value.strip()

    return headers


def serialize_otel_headers(headers: dict[str, str]) -> str:
    return ",".join(f"{key}={value}" for key, value in headers.items())
