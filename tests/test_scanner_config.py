from __future__ import annotations

from types import SimpleNamespace
import unittest

from api.scanner_config import (
    active_scanner_configs,
    ban_topics_multi_label,
    direction_supported_scanner_configs,
    duplicate_scanner_type,
    request_config_fingerprint,
    scanner_config_fingerprint,
    scanner_instantiation_params,
    scanner_supported_in_direction,
    shares_scanner_across_directions,
)


def scanner_config(
    scanner_type: str,
    params: dict | None = None,
    *,
    active: bool = True,
) -> SimpleNamespace:
    return SimpleNamespace(type=scanner_type, params=params or {}, active=active)


class ScannerConfigTests(unittest.TestCase):
    def test_direction_agnostic_scanners_share_fingerprint(self) -> None:
        config = scanner_config("BanTopics", {"topics": ["policy"], "threshold": 0.8})

        self.assertEqual(
            scanner_config_fingerprint("input", config),
            scanner_config_fingerprint("output", config),
        )

    def test_policy_thresholds_do_not_change_scanner_fingerprint(self) -> None:
        input_config = scanner_config("BanTopics", {"topics": ["policy"], "threshold": 0.8})
        output_config = scanner_config("BanTopics", {"topics": ["policy"], "threshold": 0.7})

        self.assertEqual(
            scanner_config_fingerprint("input", input_config),
            scanner_config_fingerprint("output", output_config),
        )

        low_minimum = scanner_config("FactualConsistency", {"minimum_score": 0.2})
        high_minimum = scanner_config("FactualConsistency", {"minimum_score": 0.95})
        self.assertEqual(
            scanner_config_fingerprint("output", low_minimum),
            scanner_config_fingerprint("output", high_minimum),
        )

    def test_policy_thresholds_do_not_change_request_fingerprint(self) -> None:
        first = [
            scanner_config("Toxicity", {"threshold": 0.2, "match_type": "sentence"}),
            scanner_config("FactualConsistency", {"minimum_score": 0.4}),
        ]
        second = [
            scanner_config("Toxicity", {"threshold": 0.9, "match_type": "sentence"}),
            scanner_config("FactualConsistency", {"minimum_score": 0.95}),
        ]

        self.assertEqual(
            request_config_fingerprint("output", first),
            request_config_fingerprint("output", second),
        )

    def test_non_policy_params_change_fingerprint(self) -> None:
        full = scanner_config("Toxicity", {"threshold": 0.8, "match_type": "full"})
        sentence = scanner_config("Toxicity", {"threshold": 0.8, "match_type": "sentence"})

        self.assertNotEqual(
            scanner_config_fingerprint("input", full),
            scanner_config_fingerprint("input", sentence),
        )

    def test_ban_topics_multi_label_changes_fingerprint(self) -> None:
        single_label_config = scanner_config(
            "BanTopics",
            {"topics": ["policy"], "threshold": 0.8, "multi_label": False},
        )
        multi_label_config = scanner_config(
            "BanTopics",
            {"topics": ["policy"], "threshold": 0.8, "multi_label": True},
        )

        self.assertNotEqual(
            scanner_config_fingerprint("input", single_label_config),
            scanner_config_fingerprint("input", multi_label_config),
        )

    def test_active_flag_does_not_change_fingerprint(self) -> None:
        active_config = scanner_config(
            "BanTopics",
            {"topics": ["policy"], "threshold": 0.8},
            active=True,
        )
        inactive_config = scanner_config(
            "BanTopics",
            {"topics": ["policy"], "threshold": 0.8},
            active=False,
        )

        self.assertEqual(
            scanner_config_fingerprint("input", active_config),
            scanner_config_fingerprint("input", inactive_config),
        )

    def test_active_scanner_configs_filters_inactive_configs(self) -> None:
        active_config = scanner_config("BanTopics", active=True)
        inactive_config = scanner_config("Toxicity", active=False)

        self.assertEqual(active_scanner_configs([active_config, inactive_config]), [active_config])

    def test_scanner_supported_in_direction_knows_direction_only_types(self) -> None:
        self.assertFalse(scanner_supported_in_direction("input", scanner_config("Sensitive")))
        self.assertTrue(scanner_supported_in_direction("output", scanner_config("Sensitive")))
        self.assertTrue(scanner_supported_in_direction("input", scanner_config("Anonymize")))
        self.assertFalse(scanner_supported_in_direction("output", scanner_config("Anonymize")))

    def test_direction_supported_scanner_configs_skips_unsupported_configs(self) -> None:
        supported_config = scanner_config("Anonymize")
        unsupported_config = scanner_config("Sensitive", active=False)

        self.assertEqual(
            direction_supported_scanner_configs("input", [supported_config, unsupported_config]),
            [supported_config],
        )

    def test_ban_topics_multi_label_is_not_passed_to_constructor(self) -> None:
        config = scanner_config(
            "BanTopics",
            {"topics": ["policy"], "threshold": 0.8, "multi_label": True},
        )

        self.assertEqual(
            scanner_instantiation_params(config),
            {"topics": ["policy"], "threshold": 1.0},
        )

    def test_policy_thresholds_produce_identical_stable_instantiation_params(self) -> None:
        cases = [
            ("BanCompetitors", "threshold", 1.0),
            ("BanTopics", "threshold", 1.0),
            ("Bias", "threshold", 1.0),
            ("Code", "threshold", 1.0),
            ("Gibberish", "threshold", 1.0),
            ("Language", "threshold", 1.0),
            ("MaliciousURLs", "threshold", 1.0),
            ("PromptInjection", "threshold", 1.0),
            ("Toxicity", "threshold", 1.0),
            ("Sentiment", "threshold", -1.0),
            ("Anonymize", "threshold", 0.5),
            ("Sensitive", "threshold", 0.5),
            ("Relevance", "threshold", 0.5),
            ("FactualConsistency", "minimum_score", 0.75),
        ]
        for scanner_type, param_name, stable_value in cases:
            with self.subTest(scanner_type=scanner_type):
                low = scanner_config(scanner_type, {param_name: 0.1, "use_onnx": True})
                high = scanner_config(scanner_type, {param_name: 0.9, "use_onnx": True})

                expected = {param_name: stable_value, "use_onnx": True}
                self.assertEqual(scanner_instantiation_params(low), expected)
                self.assertEqual(scanner_instantiation_params(high), expected)

    def test_ban_topics_multi_label_defaults_false(self) -> None:
        self.assertFalse(ban_topics_multi_label(scanner_config("BanTopics")))

    def test_ban_topics_multi_label_must_be_boolean(self) -> None:
        with self.assertRaises(ValueError):
            ban_topics_multi_label(scanner_config("BanTopics", {"multi_label": "true"}))

    def test_direction_specific_scanners_keep_separate_fingerprints(self) -> None:
        config = scanner_config("Sensitive", {"threshold": 0.75})

        self.assertFalse(shares_scanner_across_directions(config.type))
        self.assertNotEqual(
            scanner_config_fingerprint("input", config),
            scanner_config_fingerprint("output", config),
        )

    def test_duplicate_scanner_type_detects_repeated_type(self) -> None:
        duplicate_type = duplicate_scanner_type(
            [
                scanner_config("BanTopics", {"topics": ["one"]}),
                scanner_config("BanTopics", {"topics": ["two"]}),
            ]
        )

        self.assertEqual(duplicate_type, "BanTopics")


if __name__ == "__main__":
    unittest.main()
