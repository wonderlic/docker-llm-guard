from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field


@dataclass
class CachedScanner:
    fingerprint: str
    direction: str
    scanner_type: str
    scanner: Any
    created_at: float
    last_used_at: float
    memory_bytes: int | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass(frozen=True)
class ScannerInvocation:
    index: int
    instance_id: str
    direction: str
    scanner_type: str
    fingerprint: str
    cache_hit: bool
    scanner: Any
    lock: threading.Lock
    multi_label: bool = False


class RequestScannerConfig(BaseModel):
    type: str
    params: dict[str, Any] = Field(default_factory=dict)
    active: bool = True


class DetailedPromptScanRequest(BaseModel):
    prompt: str
    input_scanners: list[RequestScannerConfig]
    fail_fast: bool = False


class DetailedOutputScanRequest(BaseModel):
    prompt: str
    output: str
    output_scanners: list[RequestScannerConfig]
    fail_fast: bool = False


class ScannerResult(BaseModel):
    index: int
    instance_id: str
    type: str
    config_fingerprint: str
    cache_hit: bool
    is_valid: bool
    risk_score: float
    raw_score: float | None = None
    changed: bool
    threshold: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class DetailedPromptScanResponse(BaseModel):
    sanitized_prompt: str
    is_valid: bool
    risk_score: float
    config_fingerprint: str
    cache_ttl_seconds: int
    scanners: list[ScannerResult]


class DetailedOutputScanResponse(BaseModel):
    sanitized_output: str
    is_valid: bool
    risk_score: float
    config_fingerprint: str
    cache_ttl_seconds: int
    scanners: list[ScannerResult]


class CacheStatsResponse(BaseModel):
    size: int
    ttl_seconds: int
    policy: str
    input_fingerprints: list[str]
    output_fingerprints: list[str]
    memory_usage_bytes: int | None = None
    memory_limit_bytes: int | None = None
    scanners: list[dict[str, Any]]
