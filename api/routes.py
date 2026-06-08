from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import require_bearer_token
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

    return DetailedPromptScanResponse(
        sanitized_prompt=sanitized_prompt,
        is_valid=is_valid,
        risk_score=risk_score,
        config_fingerprint=request_config_fingerprint("input", active_configs),
        cache_ttl_seconds=SCANNER_CACHE_TTL_SECONDS,
        scanners=scanner_results,
    )


@router.post(
    "/scan/output/detailed",
    response_model=DetailedOutputScanResponse,
    dependencies=[Depends(require_bearer_token)],
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

    return DetailedOutputScanResponse(
        sanitized_output=sanitized_output,
        is_valid=is_valid,
        risk_score=risk_score,
        config_fingerprint=request_config_fingerprint("output", active_configs),
        cache_ttl_seconds=SCANNER_CACHE_TTL_SECONDS,
        scanners=scanner_results,
    )
