from __future__ import annotations

from app.otel import instrument_app
from fastapi import FastAPI

from api.routes import router
from api.scanner_cache import start_cache_evictor
from api.telemetry import add_trace_header_debug_middleware, configure_tracing


def create_app() -> FastAPI:
    start_cache_evictor()
    configure_tracing()
    app = FastAPI(title="Detailed LLM Guard API")
    add_trace_header_debug_middleware(app)
    app.include_router(router)
    instrument_app(app)
    return app
