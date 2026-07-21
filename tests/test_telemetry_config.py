from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import api.telemetry as telemetry


class TelemetryConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        telemetry.telemetry_configured = False

    def test_otlp_tracing_is_not_configured_without_an_endpoint(self) -> None:
        with (
            patch.dict(os.environ, {"TRACING_EXPORTER": "otel_http"}, clear=True),
            patch.object(telemetry, "configure_otel") as configure_otel,
        ):
            telemetry.configure_tracing()

        configure_otel.assert_not_called()
        self.assertFalse(telemetry.telemetry_configured)

    def test_trace_specific_standard_endpoint_is_supported(self) -> None:
        with patch.dict(
            os.environ,
            {"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://collector.test/custom/traces"},
            clear=True,
        ):
            self.assertEqual(
                telemetry.tracing_endpoint(),
                "https://collector.test/custom/traces",
            )

    def test_signal_path_is_appended_to_standard_base_endpoint(self) -> None:
        with patch.dict(
            os.environ,
            {"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.test/"},
            clear=True,
        ):
            self.assertEqual(
                telemetry.tracing_endpoint(),
                "https://collector.test/v1/traces",
            )


if __name__ == "__main__":
    unittest.main()
