from __future__ import annotations

import hashlib
import json
from typing import Any


# Presidio/Relevance/FactualConsistency values are explicit llm-guard 0.3.16
# defaults. All values are nonzero to keep risk normalization well-defined.
STABLE_SCORING_PARAMS: dict[str, tuple[str, float]] = {
    "Anonymize": ("threshold", 0.5),
    "BanCompetitors": ("threshold", 1.0),
    "BanTopics": ("threshold", 1.0),
    "Bias": ("threshold", 1.0),
    "Code": ("threshold", 1.0),
    "FactualConsistency": ("minimum_score", 0.75),
    "Gibberish": ("threshold", 1.0),
    "Language": ("threshold", 1.0),
    "MaliciousURLs": ("threshold", 1.0),
    "PromptInjection": ("threshold", 1.0),
    "Relevance": ("threshold", 0.5),
    "Sensitive": ("threshold", 0.5),
    "Sentiment": ("threshold", -1.0),
    "Toxicity": ("threshold", 1.0),
}


DIRECTION_AGNOSTIC_SCANNER_TYPES = frozenset(
    {
        "BanCode",
        "BanCompetitors",
        "BanSubstrings",
        "BanTopics",
        "Code",
        "EmotionDetection",
        "Gibberish",
        "Language",
        "Regex",
        "Sentiment",
        "Toxicity",
    }
)

INPUT_SCANNER_TYPES = frozenset(
    {
        "Anonymize",
        "BanCode",
        "BanCompetitors",
        "BanSubstrings",
        "BanTopics",
        "Code",
        "EmotionDetection",
        "Gibberish",
        "InvisibleText",
        "Language",
        "PromptInjection",
        "Regex",
        "Secrets",
        "Sentiment",
        "TokenLimit",
        "Toxicity",
    }
)

OUTPUT_SCANNER_TYPES = frozenset(
    {
        "BanCode",
        "BanCompetitors",
        "BanSubstrings",
        "BanTopics",
        "Bias",
        "Code",
        "Deanonymize",
        "EmotionDetection",
        "FactualConsistency",
        "Gibberish",
        "JSON",
        "Language",
        "LanguageSame",
        "MaliciousURLs",
        "NoRefusal",
        "NoRefusalLight",
        "ReadingTime",
        "Regex",
        "Relevance",
        "Sensitive",
        "Sentiment",
        "Toxicity",
        "URLReachability",
    }
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def normalized_scanner_params(scanner_config: Any) -> dict[str, Any]:
    params = dict(scanner_config.params or {})
    params.pop("threshold", None)
    params.pop("minimum_score", None)
    stable_scoring_param = STABLE_SCORING_PARAMS.get(scanner_config.type)
    if stable_scoring_param is not None:
        name, value = stable_scoring_param
        params[name] = value

    return params


def scanner_config_payload(direction: str, scanner_config: Any) -> dict[str, Any]:
    scanner_type = scanner_config.type
    payload = {
        "type": scanner_type,
        "params": normalized_scanner_params(scanner_config),
    }
    if scanner_type not in DIRECTION_AGNOSTIC_SCANNER_TYPES:
        payload["direction"] = direction

    return payload


def scanner_instantiation_params(scanner_config: Any) -> dict[str, Any]:
    params = normalized_scanner_params(scanner_config)
    if scanner_config.type == "BanTopics":
        params.pop("multi_label", None)

    return params


def ban_topics_multi_label(scanner_config: Any) -> bool:
    if scanner_config.type != "BanTopics":
        return False

    multi_label = (scanner_config.params or {}).get("multi_label", False)
    if isinstance(multi_label, bool):
        return multi_label

    raise ValueError("BanTopics param 'multi_label' must be a boolean")


def scanner_is_active(scanner_config: Any) -> bool:
    return bool(getattr(scanner_config, "active", True))


def active_scanner_configs(scanner_configs: list[Any]) -> list[Any]:
    return [scanner_config for scanner_config in scanner_configs if scanner_is_active(scanner_config)]


def scanner_supported_in_direction(direction: str, scanner_config: Any) -> bool:
    scanner_types = INPUT_SCANNER_TYPES if direction == "input" else OUTPUT_SCANNER_TYPES
    return scanner_config.type in scanner_types


def direction_supported_scanner_configs(direction: str, scanner_configs: list[Any]) -> list[Any]:
    return [
        scanner_config
        for scanner_config in scanner_configs
        if scanner_supported_in_direction(direction, scanner_config)
    ]


def scanner_config_fingerprint(direction: str, scanner_config: Any) -> str:
    digest = hashlib.sha256(
        canonical_json(scanner_config_payload(direction, scanner_config)).encode()
    ).hexdigest()
    return digest[:16]


def request_config_fingerprint(direction: str, scanner_configs: list[Any]) -> str:
    payload = [scanner_config_payload(direction, scanner_config) for scanner_config in scanner_configs]
    digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    return digest[:16]


def duplicate_scanner_type(scanner_configs: list[Any]) -> str | None:
    seen: set[str] = set()
    for scanner_config in scanner_configs:
        if scanner_config.type in seen:
            return scanner_config.type
        seen.add(scanner_config.type)

    return None


def shares_scanner_across_directions(scanner_type: str) -> bool:
    return scanner_type in DIRECTION_AGNOSTIC_SCANNER_TYPES
