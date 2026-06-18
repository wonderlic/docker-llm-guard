from __future__ import annotations

import json
import os
import threading
from typing import Any

from app.config import TracingConfig
from app.otel import configure_otel
from app.version import __version__
from fastapi import FastAPI, Request
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExportResult, SpanExporter

from api.health_checks import HEALTH_CHECK_PATH, exclude_health_check_tracing, is_health_check_span
from api.phoenix_config import (
    ARIZE_AX_API_VERSION,
    PHOENIX_API_VERSION,
    configure_arize_ax_tracing_headers,
    configure_phoenix_tracing_headers,
    get_arize_ax_project_name,
    get_phoenix_api_version,
    get_tracing_endpoint,
    validate_tracing_endpoint,
)
from api.telemetry_logs import suppress_transient_span_export_errors

telemetry_configured = False
telemetry_lock = threading.Lock()
tracer = trace.get_tracer("api.scanners")


def configure_tracing() -> None:
    global telemetry_configured

    exclude_health_check_tracing()

    tracing_exporter = os.environ.get("TRACING_EXPORTER", "console")
    if tracing_exporter.lower() in {"", "none", "disabled"}:
        return

    with telemetry_lock:
        if telemetry_configured:
            return

        app_name = os.environ.get("APP_NAME", "Detailed LLM Guard API")
        phoenix_api_version = get_phoenix_api_version()
        tracing_endpoint = get_tracing_endpoint(phoenix_api_version)
        validate_tracing_endpoint(phoenix_api_version, tracing_endpoint)

        if phoenix_api_version == ARIZE_AX_API_VERSION and tracing_exporter == "otel_http":
            configure_arize_ax_tracing(app_name, tracing_endpoint)
            telemetry_configured = True
            return

        if phoenix_api_version == PHOENIX_API_VERSION and tracing_exporter == "otel_http":
            configure_phoenix_tracing(app_name, tracing_endpoint)
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


def configure_arize_ax_tracing(app_name: str, endpoint: str | None) -> None:
    configure_arize_ax_tracing_headers()
    suppress_transient_span_export_errors()
    project_name = get_arize_ax_project_name(app_name)
    configure_otlp_http_tracing(app_name, endpoint, {"openinference.project.name": project_name})


def configure_phoenix_tracing(app_name: str, endpoint: str | None) -> None:
    configure_phoenix_tracing_headers(app_name)
    suppress_transient_span_export_errors()
    configure_otlp_http_tracing(app_name, endpoint, {})


def configure_otlp_http_tracing(
    app_name: str,
    endpoint: str | None,
    resource_attributes: dict[str, str],
) -> None:
    resource = Resource(
        attributes={
            SERVICE_NAME: app_name,
            SERVICE_VERSION: __version__,
            **resource_attributes,
        }
    )
    tracer_provider = TracerProvider(resource=resource)
    exporter = HealthCheckFilteringSpanExporter(OTLPSpanExporter(endpoint=endpoint))
    tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(tracer_provider)


class HealthCheckFilteringSpanExporter(SpanExporter):
    def __init__(self, exporter: SpanExporter) -> None:
        self.exporter = exporter

    def export(self, spans: object) -> SpanExportResult:
        filtered_spans = tuple(span for span in spans if not is_health_check_span(span))
        if not filtered_spans:
            return SpanExportResult.SUCCESS

        return self.exporter.export(filtered_spans)

    def shutdown(self) -> None:
        self.exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self.exporter.force_flush(timeout_millis)


def add_trace_header_debug_middleware(app: FastAPI) -> None:
    if os.environ.get("TRACE_HEADER_DEBUG", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return

    @app.middleware("http")
    async def log_trace_headers(request: Request, call_next: Any) -> Any:
        if request.url.path == HEALTH_CHECK_PATH:
            return await call_next(request)

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
