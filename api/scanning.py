from __future__ import annotations

from typing import Any

from llm_guard.util import calculate_risk_score
from opentelemetry.trace import Status, StatusCode

from api.models import ScannerInvocation, ScannerResult
from api.telemetry import tracer


def scanner_threshold(scanner: Any) -> float | None:
    threshold = getattr(scanner, "_threshold", None)
    if threshold is None and hasattr(scanner, "_scanner"):
        threshold = getattr(scanner._scanner, "_threshold", None)
    if threshold is None:
        return None

    return float(threshold)


def ban_topics_inner_scanner(scanner: Any) -> Any:
    return getattr(scanner, "_scanner", scanner)


def scan_ban_topics(scanner: Any, text: str) -> tuple[str, bool, float, dict[str, Any]]:
    inner_scanner = ban_topics_inner_scanner(scanner)
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
                "multi_label": False,
                "matched_topic": None,
                "matched_score": 0.0,
                "effective_score": 0.0,
                "topics": [],
            },
        )

    output_model = inner_scanner._classifier(text, topics, multi_label=False)
    labels = list(output_model.get("labels", []))
    scores = [float(score) for score in output_model.get("scores", [])]
    topic_scores = [
        {"topic": label, "score": score}
        for label, score in zip(labels, scores, strict=False)
    ]
    matched_index = max(range(len(scores)), key=scores.__getitem__) if scores else None
    matched_topic = labels[matched_index] if matched_index is not None else None
    matched_score = scores[matched_index] if matched_index is not None else 0.0
    effective_score = round(max(scores) if scores else 0.0, 2)
    is_valid = effective_score <= threshold
    risk_score = calculate_risk_score(effective_score, threshold)

    return (
        text,
        is_valid,
        risk_score,
        {
            "multi_label": False,
            "matched_topic": matched_topic,
            "matched_score": matched_score,
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
                    sanitized_prompt, is_valid, risk_score, details = scan_ban_topics(scanner, prompt)
                else:
                    sanitized_prompt, is_valid, risk_score = scanner.scan(prompt)
                    details = {}

            is_valid = bool(is_valid)
            risk_score = float(risk_score)

            span.set_attribute("scanner.is_valid", is_valid)
            span.set_attribute("scanner.risk_score", risk_score)
            span.set_attribute("scanner.changed", sanitized_prompt != prompt)
            return sanitized_prompt, ScannerResult(
                index=invocation.index,
                instance_id=invocation.instance_id,
                type=invocation.scanner_type,
                config_fingerprint=invocation.fingerprint,
                cache_hit=invocation.cache_hit,
                is_valid=is_valid,
                risk_score=risk_score,
                changed=sanitized_prompt != prompt,
                threshold=threshold,
                details=details,
            )
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            return prompt, ScannerResult(
                index=invocation.index,
                instance_id=invocation.instance_id,
                type=invocation.scanner_type,
                config_fingerprint=invocation.fingerprint,
                cache_hit=invocation.cache_hit,
                is_valid=False,
                risk_score=1.0,
                changed=False,
                threshold=threshold,
                error=str(exc),
            )


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
                    sanitized_output, is_valid, risk_score, details = scan_ban_topics(scanner, output)
                else:
                    sanitized_output, is_valid, risk_score = scanner.scan(prompt, output)
                    details = {}

            is_valid = bool(is_valid)
            risk_score = float(risk_score)

            span.set_attribute("scanner.is_valid", is_valid)
            span.set_attribute("scanner.risk_score", risk_score)
            span.set_attribute("scanner.changed", sanitized_output != output)
            return sanitized_output, ScannerResult(
                index=invocation.index,
                instance_id=invocation.instance_id,
                type=invocation.scanner_type,
                config_fingerprint=invocation.fingerprint,
                cache_hit=invocation.cache_hit,
                is_valid=is_valid,
                risk_score=risk_score,
                changed=sanitized_output != output,
                threshold=threshold,
                details=details,
            )
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            return output, ScannerResult(
                index=invocation.index,
                instance_id=invocation.instance_id,
                type=invocation.scanner_type,
                config_fingerprint=invocation.fingerprint,
                cache_hit=invocation.cache_hit,
                is_valid=False,
                risk_score=1.0,
                changed=False,
                threshold=threshold,
                error=str(exc),
            )
