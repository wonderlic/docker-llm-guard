from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from api.phoenix_config import (
    ARIZE_AX_TRACING_ENDPOINT,
    OTEL_TRACES_HEADERS_ENV,
    PHOENIX_TRACING_ENDPOINT,
    configure_arize_ax_tracing_headers,
    configure_phoenix_tracing_headers,
    get_phoenix_api_version,
    get_tracing_endpoint,
    is_arize_ax_endpoint,
    parse_otel_headers,
    validate_tracing_endpoint,
)


class PhoenixConfigTests(unittest.TestCase):
    def test_get_phoenix_api_version_normalizes_value(self) -> None:
        with patch.dict(os.environ, {"PHOENIX_API_VERSION": " Phoenix "}, clear=True):
            self.assertEqual(get_phoenix_api_version(), "phoenix")

    def test_phoenix_endpoint_defaults_to_local_phoenix(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(get_tracing_endpoint("phoenix"), PHOENIX_TRACING_ENDPOINT)

    def test_phoenix_endpoint_prefers_tracing_otel_endpoint(self) -> None:
        with patch.dict(
            os.environ,
            {"TRACING_OTEL_ENDPOINT": "https://phoenix.example.test/v1/traces"},
            clear=True,
        ):
            self.assertEqual(
                get_tracing_endpoint("phoenix"),
                "https://phoenix.example.test/v1/traces",
            )

    def test_arize_ax_endpoint_defaults_to_arize_ax(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(get_tracing_endpoint("arize-ax"), ARIZE_AX_TRACING_ENDPOINT)

    def test_collector_endpoint_overrides_version_defaults(self) -> None:
        with patch.dict(
            os.environ,
            {"PHOENIX_TRACING_COLLECTOR_ENDPOINT": "http://collector:4318/v1/traces"},
            clear=True,
        ):
            self.assertEqual(
                get_tracing_endpoint("phoenix"),
                "http://collector:4318/v1/traces",
            )
            self.assertEqual(
                get_tracing_endpoint("arize-ax"),
                "http://collector:4318/v1/traces",
            )

    def test_configure_phoenix_tracing_headers_sets_project_and_auth(self) -> None:
        with patch.dict(
            os.environ,
            {
                "PHOENIX_API_KEY": "secret value",
                "PHOENIX_TRACING_PROJECT_NAME": "llm-guard",
                OTEL_TRACES_HEADERS_ENV: "arize-space-id=space,arize-space-key=space-key,arize-api-key=key",
            },
            clear=True,
        ):
            configure_phoenix_tracing_headers("app-name")

            headers = parse_otel_headers(os.environ[OTEL_TRACES_HEADERS_ENV])
            self.assertEqual(headers["authorization"], "Bearer%20secret%20value")
            self.assertEqual(headers["x-project-name"], "llm-guard")
            self.assertNotIn("arize-space-id", headers)
            self.assertNotIn("arize-space-key", headers)
            self.assertNotIn("arize-api-key", headers)

    def test_configure_phoenix_tracing_headers_preserves_existing_project(self) -> None:
        with patch.dict(
            os.environ,
            {OTEL_TRACES_HEADERS_ENV: "x-project-name=existing"},
            clear=True,
        ):
            configure_phoenix_tracing_headers("app-name")

            headers = parse_otel_headers(os.environ[OTEL_TRACES_HEADERS_ENV])
            self.assertEqual(headers["x-project-name"], "existing")
            self.assertNotIn("authorization", headers)

    def test_configure_arize_ax_tracing_headers_removes_phoenix_headers(self) -> None:
        with patch.dict(
            os.environ,
            {
                "PHOENIX_SPACE_ID": "space value",
                "PHOENIX_API_KEY": "secret value",
                OTEL_TRACES_HEADERS_ENV: "authorization=Bearer%20old,x-project-name=old",
            },
            clear=True,
        ):
            configure_arize_ax_tracing_headers()

            headers = parse_otel_headers(os.environ[OTEL_TRACES_HEADERS_ENV])
            self.assertEqual(headers["arize-space-id"], "space%20value")
            self.assertEqual(headers["arize-api-key"], "secret%20value")
            self.assertNotIn("authorization", headers)
            self.assertNotIn("x-project-name", headers)

    def test_configure_arize_ax_tracing_headers_supports_space_key(self) -> None:
        with patch.dict(
            os.environ,
            {
                "PHOENIX_SPACE_KEY": "space key",
                "PHOENIX_API_KEY": "secret value",
            },
            clear=True,
        ):
            configure_arize_ax_tracing_headers()

            headers = parse_otel_headers(os.environ[OTEL_TRACES_HEADERS_ENV])
            self.assertEqual(headers["arize-space-key"], "space%20key")
            self.assertEqual(headers["arize-api-key"], "secret%20value")
            self.assertNotIn("arize-space-id", headers)

    def test_is_arize_ax_endpoint_matches_arize_host(self) -> None:
        self.assertTrue(is_arize_ax_endpoint("https://otlp.arize.com/v1/traces"))
        self.assertFalse(is_arize_ax_endpoint("https://app.phoenix.arize.com/v1/traces"))
        self.assertFalse(is_arize_ax_endpoint("http://phoenix:6006/v1/traces"))

    def test_validate_tracing_endpoint_rejects_phoenix_mode_with_arize_ax_endpoint(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "PHOENIX_API_VERSION=phoenix"):
            validate_tracing_endpoint("phoenix", "https://otlp.arize.com/v1/traces")

    def test_validate_tracing_endpoint_allows_arize_ax_mode_with_arize_ax_endpoint(self) -> None:
        validate_tracing_endpoint("arize-ax", "https://otlp.arize.com/v1/traces")


if __name__ == "__main__":
    unittest.main()
