from __future__ import annotations

import logging
import unittest

from api.telemetry_logs import (
    OTLP_HTTP_TRACE_EXPORTER_LOGGER,
    TransientSpanExportErrorFilter,
    suppress_transient_span_export_errors,
)


class TelemetryLogTests(unittest.TestCase):
    def tearDown(self) -> None:
        logging.getLogger(OTLP_HTTP_TRACE_EXPORTER_LOGGER).filters.clear()

    def test_transient_span_export_error_filter_suppresses_retry_message(self) -> None:
        record = logging.LogRecord(
            OTLP_HTTP_TRACE_EXPORTER_LOGGER,
            logging.WARNING,
            __file__,
            1,
            "Transient error %s encountered while exporting span batch, retrying in %ss.",
            ("Internal Server Error", 1),
            None,
        )

        self.assertFalse(TransientSpanExportErrorFilter().filter(record))

    def test_transient_span_export_error_filter_allows_other_messages(self) -> None:
        record = logging.LogRecord(
            OTLP_HTTP_TRACE_EXPORTER_LOGGER,
            logging.ERROR,
            __file__,
            1,
            "Failed to export span batch code: %s",
            (401,),
            None,
        )

        self.assertTrue(TransientSpanExportErrorFilter().filter(record))

    def test_suppress_transient_span_export_errors_installs_filter_once(self) -> None:
        suppress_transient_span_export_errors()
        suppress_transient_span_export_errors()

        logger = logging.getLogger(OTLP_HTTP_TRACE_EXPORTER_LOGGER)
        self.assertEqual(len(logger.filters), 1)
        self.assertIsInstance(logger.filters[0], TransientSpanExportErrorFilter)


if __name__ == "__main__":
    unittest.main()
