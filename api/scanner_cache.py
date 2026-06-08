from __future__ import annotations

import gc
import os
import threading
import time

from app import scanner as scanner_factory
from fastapi import HTTPException, status
from llm_guard.vault import Vault

from api.memory import get_memory_usage_bytes, trim_process_memory
from api.models import CachedScanner, RequestScannerConfig, ScannerInvocation
from api.scanner_config import (
    ban_topics_multi_label,
    direction_supported_scanner_configs,
    duplicate_scanner_type,
    scanner_config_fingerprint,
    scanner_instantiation_params,
    scanner_config_payload,
    scanner_is_active,
    scanner_supported_in_direction,
)
from api.telemetry import tracer


SCANNER_CACHE_TTL_SECONDS = int(os.environ.get("SCANNER_CACHE_TTL_SECONDS", str(48 * 60 * 60)))

scanner_cache_lock = threading.RLock()
scanner_cache_evictor_started = False
scanner_cache_evictor_lock = threading.Lock()
scanner_cache: dict[str, CachedScanner] = {}
scanner_cache_sets: dict[str, set[str]] = {"input": set(), "output": set()}
scanner_cache_payloads: dict[str, dict[str, object]] = {}


def evict_expired_scanners_locked(now: float) -> int:
    if SCANNER_CACHE_TTL_SECONDS <= 0:
        return 0

    expired_fingerprints = [
        fingerprint
        for fingerprint, cached_scanner in scanner_cache.items()
        if now - cached_scanner.last_used_at > SCANNER_CACHE_TTL_SECONDS
    ]
    for fingerprint in expired_fingerprints:
        delete_cached_scanner_locked(fingerprint)

    return len(expired_fingerprints)


def replace_direction_cache_set_locked(direction: str, fingerprints: list[str]) -> int:
    requested_fingerprints = set(fingerprints)
    cached_fingerprints = scanner_cache_sets.get(direction, set())
    if cached_fingerprints == requested_fingerprints:
        return 0

    evicted_count = 0
    removed_fingerprints = cached_fingerprints - requested_fingerprints
    scanner_cache_sets[direction] = requested_fingerprints

    for fingerprint in removed_fingerprints:
        if scanner_fingerprint_directions_locked(fingerprint):
            continue

        scanner_cache_payloads.pop(fingerprint, None)
        if delete_cached_scanner_locked(fingerprint):
            evicted_count += 1

    return evicted_count


def delete_cached_scanner_locked(fingerprint: str) -> bool:
    cached_scanner = scanner_cache.pop(fingerprint, None)
    scanner_cache_payloads.pop(fingerprint, None)
    for fingerprints in scanner_cache_sets.values():
        fingerprints.discard(fingerprint)

    return cached_scanner is not None


def scanner_fingerprint_directions_locked(fingerprint: str) -> list[str]:
    return sorted(
        direction
        for direction, fingerprints in scanner_cache_sets.items()
        if fingerprint in fingerprints
    )


def validate_unique_scanner_types(scanner_configs: list[RequestScannerConfig]) -> None:
    duplicate_type = duplicate_scanner_type(scanner_configs)
    if duplicate_type is None:
        return

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={
            "message": "Request must include at most one scanner of each type",
            "scanner_type": duplicate_type,
        },
    )


def validate_scanner_params(scanner_configs: list[RequestScannerConfig]) -> None:
    for scanner_config in scanner_configs:
        try:
            ban_topics_multi_label(scanner_config)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "message": str(exc),
                    "scanner_type": scanner_config.type,
                },
            ) from exc


def validate_direction_support(direction: str, scanner_configs: list[RequestScannerConfig]) -> None:
    for scanner_config in scanner_configs:
        if scanner_supported_in_direction(direction, scanner_config):
            continue
        if not scanner_is_active(scanner_config):
            continue

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Scanner type is not supported for this direction",
                "direction": direction,
                "scanner_type": scanner_config.type,
            },
        )


def collect_evicted_scanners(evicted_count: int) -> None:
    if evicted_count <= 0:
        return

    gc.collect()
    trim_process_memory()


def evict_expired_scanners() -> None:
    with scanner_cache_lock:
        evicted_count = evict_expired_scanners_locked(time.time())

    collect_evicted_scanners(evicted_count)


def cache_evictor_loop() -> None:
    interval_seconds = min(60 * 60, max(60, SCANNER_CACHE_TTL_SECONDS // 24 or 60))
    while True:
        time.sleep(interval_seconds)
        evict_expired_scanners()


def start_cache_evictor() -> None:
    global scanner_cache_evictor_started

    with scanner_cache_evictor_lock:
        if scanner_cache_evictor_started:
            return

        scanner_cache_evictor_started = True
        thread = threading.Thread(target=cache_evictor_loop, name="scanner-cache-evictor", daemon=True)
        thread.start()


def get_cached_scanner(direction: str, scanner_config: RequestScannerConfig) -> tuple[CachedScanner, bool]:
    fingerprint = scanner_config_fingerprint(direction, scanner_config)
    now = time.time()

    with scanner_cache_lock:
        expired_count = evict_expired_scanners_locked(now)
        cached_scanner = scanner_cache.get(fingerprint)
        if cached_scanner is not None:
            cached_scanner.last_used_at = now
            collect_evicted_scanners(expired_count)
            return cached_scanner, True

        collect_evicted_scanners(expired_count)

        try:
            scanner_factory_method = (
                scanner_factory._get_input_scanner
                if direction == "input"
                else scanner_factory._get_output_scanner
            )
            memory_before = get_memory_usage_bytes()
            with tracer.start_as_current_span(
                "scanner.instantiate",
                attributes={
                    "scanner.direction": direction,
                    "scanner.type": scanner_config.type,
                    "scanner.config_fingerprint": fingerprint,
                },
            ):
                scanner = scanner_factory_method(
                    scanner_config.type,
                    scanner_instantiation_params(scanner_config),
                    vault=Vault(),
                )
            memory_after = get_memory_usage_bytes()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "message": "Failed to instantiate scanner",
                    "direction": direction,
                    "scanner_type": scanner_config.type,
                    "config_fingerprint": fingerprint,
                    "error": str(exc),
                },
            ) from exc

        memory_bytes = None
        if memory_before is not None and memory_after is not None:
            memory_bytes = max(memory_after - memory_before, 0)

        cached_scanner = CachedScanner(
            fingerprint=fingerprint,
            direction=direction,
            scanner_type=scanner_config.type,
            scanner=scanner,
            created_at=now,
            last_used_at=now,
            memory_bytes=memory_bytes,
        )
        scanner_cache[fingerprint] = cached_scanner
        scanner_cache_sets.setdefault(direction, set()).add(fingerprint)

    return cached_scanner, False


def scanner_invocations(
    direction: str,
    scanner_configs: list[RequestScannerConfig],
) -> list[ScannerInvocation]:
    validate_unique_scanner_types(scanner_configs)
    validate_scanner_params(scanner_configs)
    validate_direction_support(direction, scanner_configs)
    scanner_configs = direction_supported_scanner_configs(direction, scanner_configs)
    fingerprints = [scanner_config_fingerprint(direction, scanner_config) for scanner_config in scanner_configs]
    payloads = {
        fingerprint: scanner_config_payload(direction, scanner_config)
        for fingerprint, scanner_config in zip(fingerprints, scanner_configs, strict=True)
    }
    with scanner_cache_lock:
        evicted_count = evict_expired_scanners_locked(time.time())
        scanner_cache_payloads.update(payloads)
        evicted_count += replace_direction_cache_set_locked(direction, fingerprints)

    collect_evicted_scanners(evicted_count)

    scanner_counts: dict[str, int] = {}
    invocations: list[ScannerInvocation] = []

    for index, scanner_config in enumerate(scanner_configs):
        cached_scanner, cache_hit = get_cached_scanner(direction, scanner_config)
        if not scanner_is_active(scanner_config):
            continue

        scanner_counts[scanner_config.type] = scanner_counts.get(scanner_config.type, 0) + 1
        invocations.append(
            ScannerInvocation(
                index=index,
                instance_id=f"{scanner_config.type}#{scanner_counts[scanner_config.type]}",
                direction=direction,
                scanner_type=scanner_config.type,
                fingerprint=cached_scanner.fingerprint,
                cache_hit=cache_hit,
                scanner=cached_scanner.scanner,
                lock=cached_scanner.lock,
                multi_label=ban_topics_multi_label(scanner_config),
            )
        )

    return invocations
