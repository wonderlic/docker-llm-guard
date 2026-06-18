from __future__ import annotations

import logging
import os
import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from api.health_checks import (
    HEALTH_CHECK_EXCLUDED_URL,
    HealthCheckAccessFilter,
    access_log_path,
    exclude_health_check_tracing,
    is_health_check_span,
)
from api.server import log_config_without_health_checks


class HealthCheckSuppressionTests(unittest.TestCase):
    def test_health_check_excluded_url_matches_path_and_full_url(self) -> None:
        self.assertRegex("/health", HEALTH_CHECK_EXCLUDED_URL)
        self.assertRegex("/health?ready=1", HEALTH_CHECK_EXCLUDED_URL)
        self.assertRegex("http://localhost:8000/health", HEALTH_CHECK_EXCLUDED_URL)
        self.assertRegex("https://example.test/health?ready=1", HEALTH_CHECK_EXCLUDED_URL)
        self.assertIsNone(re.fullmatch(HEALTH_CHECK_EXCLUDED_URL, "/healthz"))

    def test_access_log_path_strips_query_string(self) -> None:
        self.assertEqual(
            access_log_path(("127.0.0.1:1234", "GET", "/health?ready=1", "1.1", 200)),
            "/health",
        )

    def test_is_health_check_span_matches_name(self) -> None:
        span = SimpleNamespace(name="GET /health", attributes={})

        self.assertTrue(is_health_check_span(span))

    def test_is_health_check_span_matches_http_attributes(self) -> None:
        for attributes in (
            {"http.route": "/health"},
            {"http.target": "/health?ready=1"},
            {"url.path": "/health"},
            {"http.url": "http://localhost:8000/health"},
            {"url.full": "https://example.test/health?ready=1"},
        ):
            with self.subTest(attributes=attributes):
                span = SimpleNamespace(name="GET", attributes=attributes)

                self.assertTrue(is_health_check_span(span))

    def test_is_health_check_span_ignores_non_health_spans(self) -> None:
        span = SimpleNamespace(name="GET /scan/cache", attributes={"http.route": "/scan/cache"})

        self.assertFalse(is_health_check_span(span))

    def test_health_check_access_filter_suppresses_health_path(self) -> None:
        record = logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:1234", "GET", "/health", "1.1", 200),
            None,
        )

        self.assertFalse(HealthCheckAccessFilter().filter(record))

    def test_health_check_access_filter_allows_other_paths(self) -> None:
        record = logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:1234", "GET", "/scan/cache", "1.1", 200),
            None,
        )

        self.assertTrue(HealthCheckAccessFilter().filter(record))

    def test_log_config_installs_health_check_filter_on_access_handler(self) -> None:
        log_config = log_config_without_health_checks({"handlers": {"access": {}}})

        self.assertEqual(
            log_config["filters"]["health_check_access"]["()"],
            "api.health_checks.HealthCheckAccessFilter",
        )
        self.assertIn("health_check_access", log_config["handlers"]["access"]["filters"])

    def test_exclude_health_check_tracing_preserves_existing_values(self) -> None:
        with patch.dict(
            os.environ,
            {
                "OTEL_PYTHON_FASTAPI_EXCLUDED_URLS": "/metrics",
                "OTEL_PYTHON_EXCLUDED_URLS": f"/ready,{HEALTH_CHECK_EXCLUDED_URL}",
            },
            clear=True,
        ):
            exclude_health_check_tracing()

            self.assertEqual(
                os.environ["OTEL_PYTHON_FASTAPI_EXCLUDED_URLS"],
                f"/metrics,{HEALTH_CHECK_EXCLUDED_URL}",
            )
            self.assertEqual(
                os.environ["OTEL_PYTHON_EXCLUDED_URLS"],
                f"/ready,{HEALTH_CHECK_EXCLUDED_URL}",
            )


if __name__ == "__main__":
    unittest.main()
