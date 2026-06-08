from __future__ import annotations

from types import SimpleNamespace
import unittest

from api.scanner_config import (
    active_scanner_configs,
    ban_topics_multi_label,
    direction_supported_scanner_configs,
    duplicate_scanner_type,
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

    def test_direction_agnostic_params_change_fingerprint(self) -> None:
        input_config = scanner_config("BanTopics", {"topics": ["policy"], "threshold": 0.8})
        output_config = scanner_config("BanTopics", {"topics": ["policy"], "threshold": 0.7})

        self.assertNotEqual(
            scanner_config_fingerprint("input", input_config),
            scanner_config_fingerprint("output", output_config),
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
            {"topics": ["policy"], "threshold": 0.8},
        )

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
