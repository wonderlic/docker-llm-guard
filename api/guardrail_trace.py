from __future__ import annotations

import json
import os
from typing import Any


def guardrail_environment() -> str:
    for name in ("AI_COACH_ENVIRONMENT", "APP_ENV", "ENVIRONMENT", "DEPLOY_ENV"):
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()

    return "unknown"


def scanner_trace_record(stage: str, scanner_result: Any) -> dict[str, Any]:
    details = getattr(scanner_result, "details", {}) or {}
    matched_topic = details.get("matched_topic")
    matched_score = details.get("matched_score")
    effective_score = details.get("effective_score")

    return {
        "name": scanner_result.type,
        "stage": stage,
        "valid": scanner_result.is_valid,
        "blocked": not scanner_result.is_valid,
        "risk_score": scanner_result.risk_score,
        "raw_score": getattr(scanner_result, "raw_score", None),
        "threshold": getattr(scanner_result, "threshold", None),
        "effective_score": effective_score,
        "matched_topic": matched_topic or None,
        "matched_topic_score": matched_score if matched_topic else None,
    }


def guardrail_trace_attributes(
    stage: str,
    scanner_results: list[Any],
) -> dict[str, Any]:
    records = [scanner_trace_record(stage, scanner_result) for scanner_result in scanner_results]
    environment = guardrail_environment()
    matched_topics = sorted(
        {
            record["matched_topic"]
            for record in records
            if isinstance(record["matched_topic"], str) and record["matched_topic"]
        }
    )
    blocked_names = sorted({record["name"] for record in records if record["blocked"]})

    attributes: dict[str, Any] = {
        "deployment.environment": environment,
        "guardrail.environment": environment,
        "guardrail.stage": stage,
        "guardrail.valid": all(scanner_result.is_valid for scanner_result in scanner_results),
        "guardrail.blocked": any(not scanner_result.is_valid for scanner_result in scanner_results),
        "guardrail.risk_score": max(
            (scanner_result.risk_score for scanner_result in scanner_results),
            default=-1.0,
        ),
        "guardrail.scanner.count": len(scanner_results),
        "guardrail.scanner.names": [record["name"] for record in records],
        "guardrail.scanner.blocked_names": blocked_names,
        "guardrail.topic.matched_names": matched_topics,
        "guardrail.scanners_json": json.dumps(records, sort_keys=True, separators=(",", ":")),
    }

    for index, record in enumerate(records):
        prefix = f"guardrail.scanner.{index}"
        attributes[f"{prefix}.name"] = record["name"]
        attributes[f"{prefix}.stage"] = record["stage"]
        attributes[f"{prefix}.valid"] = record["valid"]
        attributes[f"{prefix}.blocked"] = record["blocked"]
        attributes[f"{prefix}.risk_score"] = record["risk_score"]
        if record["raw_score"] is not None:
            attributes[f"{prefix}.raw_score"] = record["raw_score"]
        if record["threshold"] is not None:
            attributes[f"{prefix}.threshold"] = record["threshold"]
        if record["effective_score"] is not None:
            attributes[f"{prefix}.effective_score"] = record["effective_score"]
        if record["matched_topic"]:
            attributes[f"{prefix}.matched_topic"] = record["matched_topic"]
        if record["matched_topic_score"] is not None:
            attributes[f"{prefix}.matched_topic_score"] = record["matched_topic_score"]

    return attributes


def set_guardrail_trace_attributes(span: Any, stage: str, scanner_results: list[Any]) -> None:
    attributes = guardrail_trace_attributes(stage, scanner_results)
    for key, value in attributes.items():
        span.set_attribute(key, value)

    update_guardrail_trace_title(span, stage, attributes["guardrail.risk_score"], attributes["guardrail.blocked"])


def update_guardrail_trace_title(span: Any, stage: str, risk_score: Any, blocked: Any) -> None:
    update_name = getattr(span, "update_name", None)
    if not callable(update_name):
        return

    base_name = getattr(span, "name", None) or f"LLM Guard {stage}"
    status = "blocked" if blocked else "valid"
    update_name(f"{base_name} guardrail.{stage}.risk={risk_score} {status}")


def update_scanner_trace_title(span: Any, scanner_result: Any) -> None:
    update_name = getattr(span, "update_name", None)
    if not callable(update_name):
        return

    status = "blocked" if not scanner_result.is_valid else "valid"
    base_name = getattr(span, "name", None) or f"Scanner: {scanner_result.instance_id}"
    update_name(f"{base_name} risk={scanner_result.risk_score} {status}")
