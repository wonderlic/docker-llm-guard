from __future__ import annotations

import time
from collections.abc import Iterable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from json import dumps
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from opentelemetry import trace

from api.auth import require_bearer_token
from api.guardrail_trace import set_guardrail_trace_attributes
from api.memory import get_memory_limit_bytes, get_memory_usage_bytes
from api.models import (
    CacheStatsResponse,
    DetailedOutputScanRequest,
    DetailedOutputScanResponse,
    DetailedPromptScanRequest,
    DetailedPromptScanResponse,
    ScannerResult,
)
from api.scanner_cache import (
    SCANNER_CACHE_TTL_SECONDS,
    scanner_cache,
    scanner_cache_lock,
    scanner_cache_sets,
    scanner_invocations,
)
from api.scanner_config import active_scanner_configs, request_config_fingerprint
from api.scanning import scan_input_scanner, scan_output_scanner


router = APIRouter()

SSE_KEEP_ALIVE_SECONDS = 15.0


def sse_event(event: str, data: Any) -> str:
    if hasattr(data, "model_dump_json"):
        payload = data.model_dump_json()
    else:
        payload = dumps(data, separators=(",", ":"))
    return f"event: {event}\ndata: {payload}\n\n"


def wait_for_future_with_keep_alive(
    future: Future[Any],
    progress: dict[str, Any],
    interval_seconds: float = SSE_KEEP_ALIVE_SECONDS,
) -> Iterator[str]:
    while True:
        try:
            future.result(timeout=interval_seconds)
            return
        except TimeoutError:
            yield sse_event("progress", progress)


def streaming_scan_response(events: Iterable[str]) -> StreamingResponse:
    return StreamingResponse(
        events,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def scan_prompt_detailed_events(request: DetailedPromptScanRequest) -> Iterator[str]:
    scanner_configs = request.input_scanners
    if not scanner_configs:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request must include at least one scanner in 'input_scanners'",
        )
    active_configs = active_scanner_configs(scanner_configs)
    invocations = scanner_invocations("input", scanner_configs)

    sanitized_prompt = request.prompt
    scanner_results: list[ScannerResult] = []

    yield sse_event("start", {"scanner_count": len(invocations), "direction": "input"})
    with ThreadPoolExecutor(max_workers=1) as executor:
        for scanner_position, invocation in enumerate(invocations, start=1):
            queued_progress = {
                "direction": "input",
                "status": "queued",
                "current": scanner_position,
                "total": len(invocations),
                "remaining": len(invocations) - scanner_position + 1,
                "index": invocation.index,
                "instance_id": invocation.instance_id,
                "type": invocation.scanner_type,
                "cache_hit": invocation.cache_hit,
            }
            running_progress = {
                **queued_progress,
                "status": "running",
                "remaining": len(invocations) - scanner_position,
            }
            yield sse_event("progress", queued_progress)
            yield sse_event(
                "scanner_start",
                running_progress,
            )

            future: Future[tuple[str, ScannerResult]] = executor.submit(
                scan_input_scanner,
                invocation,
                sanitized_prompt,
            )
            yield from wait_for_future_with_keep_alive(future, running_progress)
            sanitized_prompt, scanner_result = future.result()

            scanner_results.append(scanner_result)
            yield sse_event("scanner_complete", scanner_result)

            if request.fail_fast and not scanner_result.is_valid:
                break

    is_valid = all(scanner_result.is_valid for scanner_result in scanner_results)
    risk_score = max(
        (scanner_result.risk_score for scanner_result in scanner_results),
        default=-1.0,
    )
    set_guardrail_trace_attributes(trace.get_current_span(), "input", scanner_results)

    yield sse_event(
        "complete",
        DetailedPromptScanResponse(
            sanitized_prompt=sanitized_prompt,
            is_valid=is_valid,
            risk_score=risk_score,
            config_fingerprint=request_config_fingerprint("input", active_configs),
            cache_ttl_seconds=SCANNER_CACHE_TTL_SECONDS,
            scanners=scanner_results,
        ),
    )


def scan_output_detailed_events(request: DetailedOutputScanRequest) -> Iterator[str]:
    scanner_configs = request.output_scanners
    if not scanner_configs:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request must include at least one scanner in 'output_scanners'",
        )
    active_configs = active_scanner_configs(scanner_configs)
    invocations = scanner_invocations("output", scanner_configs)

    sanitized_output = request.output
    scanner_results: list[ScannerResult] = []

    yield sse_event("start", {"scanner_count": len(invocations), "direction": "output"})
    with ThreadPoolExecutor(max_workers=1) as executor:
        for scanner_position, invocation in enumerate(invocations, start=1):
            queued_progress = {
                "direction": "output",
                "status": "queued",
                "current": scanner_position,
                "total": len(invocations),
                "remaining": len(invocations) - scanner_position + 1,
                "index": invocation.index,
                "instance_id": invocation.instance_id,
                "type": invocation.scanner_type,
                "cache_hit": invocation.cache_hit,
            }
            running_progress = {
                **queued_progress,
                "status": "running",
                "remaining": len(invocations) - scanner_position,
            }
            yield sse_event("progress", queued_progress)
            yield sse_event(
                "scanner_start",
                running_progress,
            )

            future: Future[tuple[str, ScannerResult]] = executor.submit(
                scan_output_scanner,
                invocation,
                request.prompt,
                sanitized_output,
            )
            yield from wait_for_future_with_keep_alive(future, running_progress)
            sanitized_output, scanner_result = future.result()

            scanner_results.append(scanner_result)
            yield sse_event("scanner_complete", scanner_result)

            if request.fail_fast and not scanner_result.is_valid:
                break

    is_valid = all(scanner_result.is_valid for scanner_result in scanner_results)
    risk_score = max(
        (scanner_result.risk_score for scanner_result in scanner_results),
        default=-1.0,
    )
    set_guardrail_trace_attributes(trace.get_current_span(), "output", scanner_results)

    yield sse_event(
        "complete",
        DetailedOutputScanResponse(
            sanitized_output=sanitized_output,
            is_valid=is_valid,
            risk_score=risk_score,
            config_fingerprint=request_config_fingerprint("output", active_configs),
            cache_ttl_seconds=SCANNER_CACHE_TTL_SECONDS,
            scanners=scanner_results,
        ),
    )


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get(
    "/scan/cache",
    response_model=CacheStatsResponse,
    dependencies=[Depends(require_bearer_token)],
)
def cache_stats() -> CacheStatsResponse:
    now = time.time()
    with scanner_cache_lock:
        input_fingerprints = sorted(scanner_cache_sets["input"])
        output_fingerprints = sorted(scanner_cache_sets["output"])
        scanners = [
            {
                "config_fingerprint": cached_scanner.fingerprint,
                "direction": cached_scanner.direction,
                "directions": sorted(
                    direction
                    for direction, fingerprints in scanner_cache_sets.items()
                    if cached_scanner.fingerprint in fingerprints
                ),
                "type": cached_scanner.scanner_type,
                "age_seconds": round(now - cached_scanner.created_at, 3),
                "idle_seconds": round(now - cached_scanner.last_used_at, 3),
                "memory_bytes": cached_scanner.memory_bytes,
            }
            for cached_scanner in scanner_cache.values()
        ]

    return CacheStatsResponse(
        size=len(scanners),
        ttl_seconds=SCANNER_CACHE_TTL_SECONDS,
        policy="last-input-and-output-request",
        input_fingerprints=input_fingerprints,
        output_fingerprints=output_fingerprints,
        memory_usage_bytes=get_memory_usage_bytes(),
        memory_limit_bytes=get_memory_limit_bytes(),
        scanners=scanners,
    )


@router.post(
    "/scan/prompt/detailed",
    response_model=DetailedPromptScanResponse,
    dependencies=[Depends(require_bearer_token)],
    deprecated=True,
)
def scan_prompt_detailed(request: DetailedPromptScanRequest) -> DetailedPromptScanResponse:
    scanner_configs = request.input_scanners
    if not scanner_configs:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request must include at least one scanner in 'input_scanners'",
        )
    active_configs = active_scanner_configs(scanner_configs)

    sanitized_prompt = request.prompt
    scanner_results: list[ScannerResult] = []

    for invocation in scanner_invocations("input", scanner_configs):
        sanitized_prompt, scanner_result = scan_input_scanner(invocation, sanitized_prompt)
        scanner_results.append(scanner_result)

        if request.fail_fast and not scanner_result.is_valid:
            break

    is_valid = all(scanner_result.is_valid for scanner_result in scanner_results)
    risk_score = max(
        (scanner_result.risk_score for scanner_result in scanner_results),
        default=-1.0,
    )
    set_guardrail_trace_attributes(trace.get_current_span(), "input", scanner_results)

    return DetailedPromptScanResponse(
        sanitized_prompt=sanitized_prompt,
        is_valid=is_valid,
        risk_score=risk_score,
        config_fingerprint=request_config_fingerprint("input", active_configs),
        cache_ttl_seconds=SCANNER_CACHE_TTL_SECONDS,
        scanners=scanner_results,
    )


@router.post(
    "/scan/prompt/detailed/stream",
    dependencies=[Depends(require_bearer_token)],
)
def scan_prompt_detailed_stream(request: DetailedPromptScanRequest) -> StreamingResponse:
    return streaming_scan_response(scan_prompt_detailed_events(request))


@router.post(
    "/scan/output/detailed",
    response_model=DetailedOutputScanResponse,
    dependencies=[Depends(require_bearer_token)],
    deprecated=True,
)
def scan_output_detailed(request: DetailedOutputScanRequest) -> DetailedOutputScanResponse:
    scanner_configs = request.output_scanners
    if not scanner_configs:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request must include at least one scanner in 'output_scanners'",
        )
    active_configs = active_scanner_configs(scanner_configs)

    sanitized_output = request.output
    scanner_results: list[ScannerResult] = []

    for invocation in scanner_invocations("output", scanner_configs):
        sanitized_output, scanner_result = scan_output_scanner(
            invocation,
            request.prompt,
            sanitized_output,
        )
        scanner_results.append(scanner_result)

        if request.fail_fast and not scanner_result.is_valid:
            break

    is_valid = all(scanner_result.is_valid for scanner_result in scanner_results)
    risk_score = max(
        (scanner_result.risk_score for scanner_result in scanner_results),
        default=-1.0,
    )
    set_guardrail_trace_attributes(trace.get_current_span(), "output", scanner_results)

    return DetailedOutputScanResponse(
        sanitized_output=sanitized_output,
        is_valid=is_valid,
        risk_score=risk_score,
        config_fingerprint=request_config_fingerprint("output", active_configs),
        cache_ttl_seconds=SCANNER_CACHE_TTL_SECONDS,
        scanners=scanner_results,
    )


@router.post(
    "/scan/output/detailed/stream",
    dependencies=[Depends(require_bearer_token)],
)
def scan_output_detailed_stream(request: DetailedOutputScanRequest) -> StreamingResponse:
    return streaming_scan_response(scan_output_detailed_events(request))
