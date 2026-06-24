from __future__ import annotations

import logging


OTLP_HTTP_TRACE_EXPORTER_LOGGER = "opentelemetry.exporter.otlp.proto.http.trace_exporter"
TRANSIENT_SPAN_EXPORT_ERROR_FILTER = "transient_span_export_error_filter"


class TransientSpanExportErrorFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        return not (
            message.startswith("Transient error ")
            and "encountered while exporting span batch" in message
        )


def suppress_transient_span_export_errors() -> None:
    logger = logging.getLogger(OTLP_HTTP_TRACE_EXPORTER_LOGGER)
    for log_filter in logger.filters:
        if getattr(log_filter, "name", None) == TRANSIENT_SPAN_EXPORT_ERROR_FILTER:
            return

    logger.addFilter(TransientSpanExportErrorFilter(TRANSIENT_SPAN_EXPORT_ERROR_FILTER))
