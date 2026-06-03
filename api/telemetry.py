from __future__ import annotations

import json
import os
import threading
from typing import Any
from urllib.parse import quote

from app.config import TracingConfig
from app.otel import configure_otel
from app.version import __version__
from fastapi import FastAPI, Request
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


ARIZE_AX_API_VERSION = "arize-ax"
ARIZE_AX_TRACING_ENDPOINT = "https://otlp.arize.com/v1/traces"
OTEL_TRACES_HEADERS_ENV = "OTEL_EXPORTER_OTLP_TRACES_HEADERS"

telemetry_configured = False
telemetry_lock = threading.Lock()
tracer = trace.get_tracer("api.scanners")


def configure_tracing() -> None:
    global telemetry_configured

    tracing_exporter = os.environ.get("TRACING_EXPORTER", "console")
    if tracing_exporter.lower() in {"", "none", "disabled"}:
        return

    with telemetry_lock:
        if telemetry_configured:
            return

        app_name = os.environ.get("APP_NAME", "Detailed LLM Guard API")
        phoenix_api_version = get_env_value("PHOENIX_API_VERSION", "PHOENIX.API_VERSION")
        tracing_endpoint = get_tracing_endpoint(phoenix_api_version)

        if phoenix_api_version == ARIZE_AX_API_VERSION and tracing_exporter == "otel_http":
            configure_arize_ax_tracing(app_name, tracing_endpoint)
            telemetry_configured = True
            return

        configure_otel(
            app_name,
            TracingConfig(
                exporter=tracing_exporter,
                endpoint=tracing_endpoint,
            ),
            None,
        )
        telemetry_configured = True


def get_env_value(*names: str) -> str:
    for name in names:
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()

    return ""


def get_tracing_endpoint(phoenix_api_version: str) -> str | None:
    phoenix_endpoint = get_env_value(
        "PHOENIX_TRACING_COLLECTOR_ENDPOINT",
        "PHOENIX.TRACING.COLLECTOR_ENDPOINT",
    )
    if phoenix_api_version == ARIZE_AX_API_VERSION:
        return phoenix_endpoint or ARIZE_AX_TRACING_ENDPOINT

    return phoenix_endpoint or get_env_value("TRACING_OTEL_ENDPOINT") or None


def configure_arize_ax_tracing(app_name: str, endpoint: str | None) -> None:
    configure_arize_ax_tracing_headers()
    project_name = get_arize_ax_project_name(app_name)
    resource = Resource(
        attributes={
            SERVICE_NAME: app_name,
            SERVICE_VERSION: __version__,
            "openinference.project.name": project_name,
        }
    )
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(tracer_provider)


def configure_arize_ax_tracing_headers() -> None:
    space_id = get_env_value("PHOENIX_SPACE_ID", "PHOENIX.SPACE_ID", "ARIZE_SPACE_ID")
    api_key = get_env_value("PHOENIX_API_KEY", "PHOENIX.API_KEY", "ARIZE_API_KEY")
    if not space_id:
        raise RuntimeError("Arize AX tracing is enabled but PHOENIX_SPACE_ID is not configured")
    if not api_key:
        raise RuntimeError("Arize AX tracing is enabled but PHOENIX_API_KEY is not configured")

    headers = parse_otel_headers(os.environ.get(OTEL_TRACES_HEADERS_ENV, ""))
    headers.pop("authorization", None)
    headers.pop("x-project-name", None)
    headers["arize-space-id"] = quote(space_id, safe="")
    headers["arize-api-key"] = quote(api_key, safe="")
    os.environ[OTEL_TRACES_HEADERS_ENV] = serialize_otel_headers(headers)


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


def add_trace_header_debug_middleware(app: FastAPI) -> None:
    if os.environ.get("TRACE_HEADER_DEBUG", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return

    @app.middleware("http")
    async def log_trace_headers(request: Request, call_next: Any) -> Any:
        span_context = trace.get_current_span().get_span_context()
        active_trace_id = f"{span_context.trace_id:032x}" if span_context.is_valid else None
        active_span_id = f"{span_context.span_id:016x}" if span_context.is_valid else None

        print(
            json.dumps(
                {
                    "event": "trace_header_debug",
                    "method": request.method,
                    "path": request.url.path,
                    "traceparent": request.headers.get("traceparent"),
                    "tracestate_present": "tracestate" in request.headers,
                    "baggage_present": "baggage" in request.headers,
                    "active_trace_id": active_trace_id,
                    "active_span_id": active_span_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )

        return await call_next(request)
