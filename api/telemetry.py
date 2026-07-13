from __future__ import annotations

import json
import os
import threading
from typing import Any

from app.config import TracingConfig
from app.otel import configure_otel
from fastapi import FastAPI, Request
from opentelemetry import trace

from api.health_checks import HEALTH_CHECK_PATH, exclude_health_check_tracing
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
        tracing_endpoint = os.environ.get("TRACING_OTEL_ENDPOINT") or None
        if tracing_exporter == "otel_http":
            suppress_transient_span_export_errors()

        configure_otel(
            app_name,
            TracingConfig(
                exporter=tracing_exporter,
                endpoint=tracing_endpoint,
            ),
            None,
        )
        telemetry_configured = True


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
