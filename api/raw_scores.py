from __future__ import annotations

import math
import unicodedata
from typing import Any


_TOXIC_LABELS = {
    "toxicity",
    "severe_toxicity",
    "obscene",
    "threat",
    "insult",
    "identity_attack",
    "sexual_explicit",
}
_GIBBERISH_LABELS = {"word salad", "noise", "mild gibberish"}
_MALICIOUS_URL_LABELS = {"defacement", "phishing", "malware"}

# This adapter intentionally follows llm-guard 0.3.16 private attributes and output
# shapes. Keeping the contract here makes a future llm-guard upgrade auditable.
_CAPTURE_TARGETS: dict[str, tuple[str, str | None]] = {
    "Anonymize": ("_analyzer", "analyze"),
    "BanCompetitors": ("_ner_pipeline", None),
    "Bias": ("_classifier", None),
    "Code": ("_pipeline", None),
    "FactualConsistency": ("_model", None),
    "Gibberish": ("_classifier", None),
    "Language": ("_pipeline", None),
    "MaliciousURLs": ("_classifier", None),
    "PromptInjection": ("_pipeline", None),
    "Relevance": ("_encode", None),
    "Sensitive": ("_analyzer", "analyze"),
    "Sentiment": ("_sentiment_analyzer", "polarity_scores"),
    "TokenLimit": ("_split_text_on_tokens", None),
    "Toxicity": ("_pipeline", None),
}
_ZERO_WHEN_NOT_EVALUATED = frozenset(_CAPTURE_TARGETS) | {
    "BanCompetitors",
    "Bias",
    "Code",
    "Gibberish",
    "InvisibleText",
    "Language",
    "MaliciousURLs",
    "PromptInjection",
    "Secrets",
    "Toxicity",
}
def _finite_float(value: Any) -> float | None:
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


class _CallRecorder:
    def __init__(self, target: Any) -> None:
        self.target = target
        self.results: list[Any] = []

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        result = self.target(*args, **kwargs)
        self.results.append(result)
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self.target, name)


class _MethodRecorder:
    def __init__(self, target: Any, method_name: str, recorder: _CallRecorder) -> None:
        self._target = target
        self._method_name = method_name
        self._recorder = recorder

    def __getattr__(self, name: str) -> Any:
        if name == self._method_name:
            return self._recorder
        return getattr(self._target, name)


class RawScoreCapture:
    def __init__(self, scanner_type: str, scanner: Any) -> None:
        self.scanner_type = scanner_type
        self.scanner = scanner
        self.attribute_name: str | None = None
        self.original: Any = None
        self.recorder: _CallRecorder | None = None

    def install(self) -> None:
        target = _CAPTURE_TARGETS.get(self.scanner_type)
        if target is None:
            return

        attribute_name, method_name = target
        original = getattr(self.scanner, attribute_name, None)
        if original is None:
            return

        recorder_target = original if method_name is None else getattr(original, method_name)
        self.attribute_name = attribute_name
        self.original = original
        self.recorder = _CallRecorder(recorder_target)
        replacement = (
            self.recorder
            if method_name is None
            else _MethodRecorder(original, method_name, self.recorder)
        )
        setattr(self.scanner, attribute_name, replacement)

    def uninstall(self) -> None:
        if self.attribute_name is not None:
            setattr(self.scanner, self.attribute_name, self.original)

    @property
    def results(self) -> list[Any]:
        return self.recorder.results if self.recorder is not None else []


def _flatten_pipeline_results(results: list[Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    pending = list(results)
    while pending:
        item = pending.pop(0)
        if isinstance(item, dict):
            items.append(item)
        elif isinstance(item, (list, tuple)):
            pending[0:0] = item
    return items


def _max_score(items: list[dict[str, Any]], labels: set[str] | None = None) -> float:
    scores = [
        score
        for item in items
        if labels is None or item.get("label") in labels
        if (score := _finite_float(item.get("score"))) is not None
    ]
    return max(scores, default=0.0)


def raw_score_from_capture(
    scanner_type: str,
    scanner: Any,
    capture_results: list[Any],
    text: str,
    sanitized_text: str,
) -> float | None:
    if scanner_type == "Deanonymize":
        return None
    if scanner_type == "InvisibleText":
        banned = set(getattr(scanner, "_banned_categories", ["Cf", "Co", "Cn"]))
        return float(sum(unicodedata.category(char) in banned for char in text))
    if scanner_type == "Secrets":
        return float(sanitized_text != text)
    if not capture_results:
        return 0.0 if scanner_type in _ZERO_WHEN_NOT_EVALUATED else None

    if scanner_type in {"Anonymize", "Sensitive"}:
        entities = capture_results[-1]
        return round(
            max(
                (_finite_float(getattr(entity, "score", None)) or 0.0 for entity in entities),
                default=0.0,
            ),
            2,
        )
    if scanner_type == "Sentiment":
        return _finite_float(capture_results[-1].get("compound"))
    if scanner_type == "TokenLimit":
        return _finite_float(capture_results[-1][1])
    if scanner_type == "Relevance":
        if len(capture_results) < 2:
            return None
        return _finite_float(capture_results[-2].dot(capture_results[-1].T))
    if scanner_type == "FactualConsistency":
        logits = capture_results[-1]["logits"][0]
        probabilities = logits.softmax(-1).tolist()
        return round(float(probabilities[0]), 2)

    items = _flatten_pipeline_results(capture_results)
    if scanner_type == "BanCompetitors":
        competitors = set(getattr(scanner, "_competitors", []))
        return _max_score(
            [item for item in items if str(item.get("word", "")).strip() in competitors]
        )
    if scanner_type == "Code":
        languages = set(getattr(scanner, "_languages", []))
        return max(
            (round(float(item["score"]), 2) for item in items if item.get("label") in languages),
            default=0.0,
        )
    if scanner_type == "Language":
        valid_languages = set(getattr(scanner, "_valid_languages", []))
        return _max_score([item for item in items if item.get("label") not in valid_languages])
    if scanner_type == "Toxicity":
        return _max_score(items, _TOXIC_LABELS)
    if scanner_type == "MaliciousURLs":
        return _max_score(items, _MALICIOUS_URL_LABELS)
    if scanner_type == "PromptInjection":
        return max(
            (
                round(score if item.get("label") == "INJECTION" else 1 - score, 2)
                for item in items
                if (score := _finite_float(item.get("score"))) is not None
            ),
            default=0.0,
        )
    if scanner_type == "Gibberish":
        return max(
            (
                round(score if item.get("label") in _GIBBERISH_LABELS else 1 - score, 2)
                for item in items
                if (score := _finite_float(item.get("score"))) is not None
            ),
            default=0.0,
        )
    if scanner_type == "Bias":
        return max(
            (
                round(score if item.get("label") == "BIASED" else 1 - score, 2)
                for item in items
                if (score := _finite_float(item.get("score"))) is not None
            ),
            default=0.0,
        )

    return None


def _presidio_raw_score(scanner_type: str, scanner: Any, text: str) -> float:
    kwargs: dict[str, Any] = {
        "text": text.replace("'", " "),
        "language": getattr(scanner, "_language", "en"),
        "entities": getattr(scanner, "_entity_types"),
        "score_threshold": 0.0,
    }
    if scanner_type == "Anonymize":
        kwargs["allow_list"] = getattr(scanner, "_allowed_names", None)

    entities = scanner._analyzer.analyze(**kwargs)
    return round(
        max(
            (_finite_float(getattr(entity, "score", None)) or 0.0 for entity in entities),
            default=0.0,
        ),
        2,
    )


def complete_raw_score(
    scanner_type: str,
    scanner: Any,
    canonical_capture_results: list[Any],
    text: str,
    sanitized_text: str,
) -> float | None:
    if scanner_type in {"Anonymize", "Sensitive"}:
        if not text.strip():
            return 0.0
        # Presidio applies score_threshold after inference, so a second analyzer
        # pass is required to expose confidences hidden by the stable constructor threshold.
        return _presidio_raw_score(scanner_type, scanner, text)

    # Stable constructor thresholds make canonical inference complete for every
    # non-Presidio scanner, including Relevance and FactualConsistency.
    return raw_score_from_capture(
        scanner_type,
        scanner,
        canonical_capture_results,
        text,
        sanitized_text,
    )
