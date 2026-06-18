from __future__ import annotations

import json
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from api.guardrail_trace import (
    guardrail_trace_attributes,
    set_guardrail_trace_attributes,
    update_scanner_trace_title,
)


class RecordingSpan:
    def __init__(self) -> None:
        self.name = "POST /scan/output/detailed"
        self.attributes: dict[str, object] = {}

    def set_attribute(self, key: str, value: object) -> None:
        self.attributes[key] = value

    def update_name(self, name: str) -> None:
        self.name = name


class GuardrailTraceTests(unittest.TestCase):
    def test_guardrail_trace_attributes_include_all_scanner_results(self) -> None:
        scanner_results = [
            SimpleNamespace(
                index=0,
                instance_id="input-BanTopics-0",
                type="BanTopics",
                config_fingerprint="abc",
                cache_hit=True,
                is_valid=False,
                risk_score=0.82,
                changed=False,
                threshold=0.75,
                details={
                    "matched_topic": "recipes",
                    "matched_score": 0.91,
                    "effective_score": 0.91,
                },
            ),
            SimpleNamespace(
                index=1,
                instance_id="input-Toxicity-1",
                type="Toxicity",
                config_fingerprint="def",
                cache_hit=False,
                is_valid=True,
                risk_score=0.31,
                changed=False,
                threshold=0.8,
            ),
        ]

        with patch.dict(os.environ, {"APP_ENV": "alpha"}, clear=True):
            attributes = guardrail_trace_attributes("input", scanner_results)

        self.assertEqual(attributes["deployment.environment"], "alpha")
        self.assertEqual(attributes["guardrail.environment"], "alpha")
        self.assertEqual(attributes["guardrail.stage"], "input")
        self.assertFalse(attributes["guardrail.valid"])
        self.assertTrue(attributes["guardrail.blocked"])
        self.assertEqual(attributes["guardrail.risk_score"], 0.82)
        self.assertEqual(attributes["guardrail.scanner.count"], 2)
        self.assertEqual(attributes["guardrail.scanner.names"], ["BanTopics", "Toxicity"])
        self.assertEqual(attributes["guardrail.scanner.blocked_names"], ["BanTopics"])
        self.assertEqual(attributes["guardrail.topic.matched_names"], ["recipes"])
        self.assertEqual(attributes["guardrail.scanner.0.name"], "BanTopics")
        self.assertEqual(attributes["guardrail.scanner.0.stage"], "input")
        self.assertFalse(attributes["guardrail.scanner.0.valid"])
        self.assertTrue(attributes["guardrail.scanner.0.blocked"])
        self.assertEqual(attributes["guardrail.scanner.0.risk_score"], 0.82)
        self.assertEqual(attributes["guardrail.scanner.0.threshold"], 0.75)
        self.assertEqual(attributes["guardrail.scanner.0.effective_score"], 0.91)
        self.assertEqual(attributes["guardrail.scanner.0.matched_topic"], "recipes")
        self.assertEqual(attributes["guardrail.scanner.0.matched_topic_score"], 0.91)
        self.assertNotIn("guardrail.scanner.1.matched_topic", attributes)

        payload = json.loads(str(attributes["guardrail.scanners_json"]))
        self.assertEqual(payload[0]["name"], "BanTopics")
        self.assertEqual(payload[0]["matched_topic"], "recipes")
        self.assertIsNone(payload[1]["matched_topic"])

    def test_set_guardrail_trace_attributes_writes_to_span(self) -> None:
        span = RecordingSpan()
        scanner_results = [
            SimpleNamespace(
                index=0,
                instance_id="output-FactualConsistency-0",
                type="FactualConsistency",
                config_fingerprint="abc",
                cache_hit=True,
                is_valid=True,
                risk_score=0.2,
                changed=False,
            )
        ]

        with patch.dict(os.environ, {}, clear=True):
            set_guardrail_trace_attributes(span, "output", scanner_results)

        self.assertEqual(span.attributes["guardrail.environment"], "unknown")
        self.assertEqual(span.attributes["guardrail.stage"], "output")
        self.assertEqual(span.attributes["guardrail.scanner.0.name"], "FactualConsistency")
        self.assertEqual(
            span.name,
            "POST /scan/output/detailed guardrail.output.risk=0.2 valid",
        )

    def test_update_scanner_trace_title_includes_risk_score(self) -> None:
        span = RecordingSpan()
        span.name = "Scanner: input-BanTopics-0"
        scanner_result = SimpleNamespace(
            instance_id="input-BanTopics-0",
            is_valid=False,
            risk_score=0.82,
        )

        update_scanner_trace_title(span, scanner_result)

        self.assertEqual(span.name, "Scanner: input-BanTopics-0 risk=0.82 blocked")


if __name__ == "__main__":
    unittest.main()
