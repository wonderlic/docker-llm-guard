from __future__ import annotations

import gc
import hashlib
import json
import os
import threading
import time
from typing import Any

from app import scanner as scanner_factory
from fastapi import HTTPException, status
from llm_guard.vault import Vault

from api.memory import get_memory_usage_bytes, trim_process_memory
from api.models import CachedScanner, RequestScannerConfig, ScannerInvocation
from api.telemetry import tracer


SCANNER_CACHE_TTL_SECONDS = int(os.environ.get("SCANNER_CACHE_TTL_SECONDS", str(48 * 60 * 60)))

scanner_cache_lock = threading.RLock()
scanner_cache_evictor_started = False
scanner_cache_evictor_lock = threading.Lock()
scanner_cache: dict[str, CachedScanner] = {}
scanner_cache_sets: dict[str, set[str]] = {"input": set(), "output": set()}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def scanner_config_payload(direction: str, scanner_config: RequestScannerConfig) -> dict[str, Any]:
    return {
        "direction": direction,
        "type": scanner_config.type,
        "params": scanner_config.params or {},
    }


def scanner_config_fingerprint(direction: str, scanner_config: RequestScannerConfig) -> str:
    digest = hashlib.sha256(
        canonical_json(scanner_config_payload(direction, scanner_config)).encode()
    ).hexdigest()
    return digest[:16]


def request_config_fingerprint(direction: str, scanner_configs: list[RequestScannerConfig]) -> str:
    payload = [scanner_config_payload(direction, scanner_config) for scanner_config in scanner_configs]
    digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    return digest[:16]


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
    for fingerprint in cached_fingerprints - requested_fingerprints:
        if delete_cached_scanner_locked(fingerprint):
            evicted_count += 1

    scanner_cache_sets[direction] = requested_fingerprints
    return evicted_count


def delete_cached_scanner_locked(fingerprint: str) -> bool:
    cached_scanner = scanner_cache.pop(fingerprint, None)
    for fingerprints in scanner_cache_sets.values():
        fingerprints.discard(fingerprint)

    return cached_scanner is not None


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
                    dict(scanner_config.params or {}),
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
    fingerprints = [scanner_config_fingerprint(direction, scanner_config) for scanner_config in scanner_configs]
    with scanner_cache_lock:
        evicted_count = evict_expired_scanners_locked(time.time())
        evicted_count += replace_direction_cache_set_locked(direction, fingerprints)

    collect_evicted_scanners(evicted_count)

    scanner_counts: dict[str, int] = {}
    invocations: list[ScannerInvocation] = []

    for index, scanner_config in enumerate(scanner_configs):
        scanner_counts[scanner_config.type] = scanner_counts.get(scanner_config.type, 0) + 1
        cached_scanner, cache_hit = get_cached_scanner(direction, scanner_config)
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
            )
        )

    return invocations
