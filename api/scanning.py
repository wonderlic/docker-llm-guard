from __future__ import annotations

import math
from typing import Any

from llm_guard.util import calculate_risk_score
from opentelemetry.trace import Status, StatusCode

from api.guardrail_trace import update_scanner_trace_title
from api.models import ScannerInvocation, ScannerResult
from api.raw_scores import RawScoreCapture, complete_raw_score
from api.scanner_config import shares_scanner_across_directions
from api.telemetry import tracer


def set_scanner_span_attributes(span: Any, scanner_result: ScannerResult) -> None:
    span.set_attribute("scanner.is_valid", scanner_result.is_valid)
    span.set_attribute("scanner.blocked", not scanner_result.is_valid)
    span.set_attribute("scanner.risk_score", scanner_result.risk_score)
    if scanner_result.raw_score is not None:
        span.set_attribute("scanner.raw_score", scanner_result.raw_score)
    if scanner_result.threshold is not None:
        span.set_attribute("scanner.threshold", scanner_result.threshold)

    effective_score = scanner_result.details.get("effective_score")
    if effective_score is not None:
        span.set_attribute("scanner.effective_score", effective_score)

    matched_topic = scanner_result.details.get("matched_topic")
    if matched_topic:
        span.set_attribute("scanner.matched_topic", matched_topic)
        span.set_attribute("scanner.matched_topic_score", scanner_result.details.get("matched_score", 0.0))


def finite_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError):
        return default

    if not math.isfinite(result):
        return default

    return result


def finite_float_or_none(value: Any) -> float | None:
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError):
        return None

    if not math.isfinite(result):
        return None

    return result


def finite_risk_score(value: Any, is_valid: bool) -> float:
    return finite_float(value, default=0.0 if is_valid else 1.0)


def calculate_finite_risk_score(score: float, threshold: float, is_valid: bool) -> float:
    try:
        return finite_risk_score(calculate_risk_score(score, threshold), is_valid)
    except ZeroDivisionError:
        return finite_risk_score(None, is_valid)


def scanner_threshold(scanner: Any) -> float | None:
    threshold = getattr(scanner, "_threshold", None)
    if threshold is None and hasattr(scanner, "_scanner"):
        threshold = getattr(scanner._scanner, "_threshold", None)
    if threshold is None:
        return None

    return finite_float_or_none(threshold)


def shared_inner_scanner(scanner: Any) -> Any:
    return getattr(scanner, "_scanner", scanner)


def scan_ban_topics(
    scanner: Any,
    text: str,
    *,
    multi_label: bool = False,
) -> tuple[str, bool, float, dict[str, Any]]:
    inner_scanner = shared_inner_scanner(scanner)
    topics = list(getattr(inner_scanner, "_topics", []))
    threshold = scanner_threshold(inner_scanner)
    if threshold is None:
        threshold = 0.0

    if text.strip() == "":
        return (
            text,
            True,
            -1.0,
            {
                "multi_label": multi_label,
                "matched_topic": None,
                "matched_score": 0.0,
                "matched_topics": [],
                "effective_score": 0.0,
                "topics": [],
            },
        )

    output_model = inner_scanner._classifier(text, topics, multi_label=multi_label)
    labels = list(output_model.get("labels", []))
    scores = [finite_float(score) for score in output_model.get("scores", [])]
    topic_scores = [
        {"topic": label, "score": score}
        for label, score in zip(labels, scores, strict=False)
    ]
    matched_index = max(range(len(scores)), key=scores.__getitem__) if scores else None
    matched_topic = labels[matched_index] if matched_index is not None else None
    matched_score = scores[matched_index] if matched_index is not None else 0.0
    effective_score = round(max(scores) if scores else 0.0, 2)
    is_valid = effective_score <= threshold
    risk_score = calculate_finite_risk_score(effective_score, threshold, is_valid)
    matched_topics = [
        topic_score
        for topic_score in topic_scores
        if round(topic_score["score"], 2) > threshold
    ]

    return (
        text,
        is_valid,
        risk_score,
        {
            "multi_label": multi_label,
            "matched_topic": matched_topic,
            "matched_score": matched_score,
            "matched_topics": matched_topics,
            "effective_score": effective_score,
            "topics": topic_scores,
        },
    )


def scan_input_scanner(invocation: ScannerInvocation, prompt: str) -> tuple[str, ScannerResult]:
    scanner = invocation.scanner
    threshold = scanner_threshold(scanner)
    with tracer.start_as_current_span(
        f"Scanner: {invocation.instance_id}",
        attributes={
            "scanner.direction": invocation.direction,
            "scanner.type": invocation.scanner_type,
            "scanner.instance_id": invocation.instance_id,
            "scanner.config_fingerprint": invocation.fingerprint,
            "scanner.cache_hit": invocation.cache_hit,
        },
    ) as span:
        try:
            with invocation.lock:
                if invocation.scanner_type == "BanTopics":
                    sanitized_prompt, is_valid, risk_score, details = scan_ban_topics(
                        scanner,
                        prompt,
                        multi_label=invocation.multi_label,
                    )
                    raw_score = finite_float_or_none(details["effective_score"])
                elif shares_scanner_across_directions(invocation.scanner_type):
                    inner_scanner = shared_inner_scanner(scanner)
                    capture = RawScoreCapture(invocation.scanner_type, inner_scanner)
                    capture.install()
                    try:
                        sanitized_prompt, is_valid, risk_score = inner_scanner.scan(prompt)
                    finally:
                        capture.uninstall()
                    details = {}
                    raw_score = complete_raw_score(
                        invocation.scanner_type,
                        inner_scanner,
                        capture.results,
                        prompt,
                        sanitized_prompt,
                    )
                else:
                    capture = RawScoreCapture(invocation.scanner_type, scanner)
                    capture.install()
                    try:
                        sanitized_prompt, is_valid, risk_score = scanner.scan(prompt)
                    finally:
                        capture.uninstall()
                    details = {}
                    raw_score = complete_raw_score(
                        invocation.scanner_type,
                        scanner,
                        capture.results,
                        prompt,
                        sanitized_prompt,
                    )

            is_valid = bool(is_valid)
            risk_score = finite_risk_score(risk_score, is_valid)

            scanner_result = ScannerResult(
                index=invocation.index,
                instance_id=invocation.instance_id,
                type=invocation.scanner_type,
                config_fingerprint=invocation.fingerprint,
                cache_hit=invocation.cache_hit,
                is_valid=is_valid,
                risk_score=risk_score,
                raw_score=raw_score,
                changed=sanitized_prompt != prompt,
                threshold=threshold,
                details=details,
            )
            set_scanner_span_attributes(span, scanner_result)
            span.set_attribute("scanner.changed", scanner_result.changed)
            update_scanner_trace_title(span, scanner_result)
            return sanitized_prompt, scanner_result
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            scanner_result = ScannerResult(
                index=invocation.index,
                instance_id=invocation.instance_id,
                type=invocation.scanner_type,
                config_fingerprint=invocation.fingerprint,
                cache_hit=invocation.cache_hit,
                is_valid=False,
                risk_score=1.0,
                raw_score=None,
                changed=False,
                threshold=threshold,
                error=str(exc),
            )
            set_scanner_span_attributes(span, scanner_result)
            update_scanner_trace_title(span, scanner_result)
            return prompt, scanner_result


def scan_output_scanner(
    invocation: ScannerInvocation,
    prompt: str,
    output: str,
) -> tuple[str, ScannerResult]:
    scanner = invocation.scanner
    threshold = scanner_threshold(scanner)
    with tracer.start_as_current_span(
        f"Scanner: {invocation.instance_id}",
        attributes={
            "scanner.direction": invocation.direction,
            "scanner.type": invocation.scanner_type,
            "scanner.instance_id": invocation.instance_id,
            "scanner.config_fingerprint": invocation.fingerprint,
            "scanner.cache_hit": invocation.cache_hit,
        },
    ) as span:
        try:
            with invocation.lock:
                if invocation.scanner_type == "BanTopics":
                    sanitized_output, is_valid, risk_score, details = scan_ban_topics(
                        scanner,
                        output,
                        multi_label=invocation.multi_label,
                    )
                    raw_score = finite_float_or_none(details["effective_score"])
                elif shares_scanner_across_directions(invocation.scanner_type):
                    inner_scanner = shared_inner_scanner(scanner)
                    capture = RawScoreCapture(invocation.scanner_type, inner_scanner)
                    capture.install()
                    try:
                        sanitized_output, is_valid, risk_score = inner_scanner.scan(output)
                    finally:
                        capture.uninstall()
                    details = {}
                    raw_score = complete_raw_score(
                        invocation.scanner_type,
                        inner_scanner,
                        capture.results,
                        output,
                        sanitized_output,
                    )
                else:
                    capture = RawScoreCapture(invocation.scanner_type, scanner)
                    capture.install()
                    try:
                        sanitized_output, is_valid, risk_score = scanner.scan(prompt, output)
                    finally:
                        capture.uninstall()
                    details = {}
                    raw_score = complete_raw_score(
                        invocation.scanner_type,
                        scanner,
                        capture.results,
                        output,
                        sanitized_output,
                    )

            is_valid = bool(is_valid)
            risk_score = finite_risk_score(risk_score, is_valid)

            scanner_result = ScannerResult(
                index=invocation.index,
                instance_id=invocation.instance_id,
                type=invocation.scanner_type,
                config_fingerprint=invocation.fingerprint,
                cache_hit=invocation.cache_hit,
                is_valid=is_valid,
                risk_score=risk_score,
                raw_score=raw_score,
                changed=sanitized_output != output,
                threshold=threshold,
                details=details,
            )
            set_scanner_span_attributes(span, scanner_result)
            span.set_attribute("scanner.changed", scanner_result.changed)
            update_scanner_trace_title(span, scanner_result)
            return sanitized_output, scanner_result
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            scanner_result = ScannerResult(
                index=invocation.index,
                instance_id=invocation.instance_id,
                type=invocation.scanner_type,
                config_fingerprint=invocation.fingerprint,
                cache_hit=invocation.cache_hit,
                is_valid=False,
                risk_score=1.0,
                raw_score=None,
                changed=False,
                threshold=threshold,
                error=str(exc),
            )
            set_scanner_span_attributes(span, scanner_result)
            update_scanner_trace_title(span, scanner_result)
            return output, scanner_result
