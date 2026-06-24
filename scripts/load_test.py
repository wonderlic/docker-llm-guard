#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import shlex
import statistics
import sys
import time
from typing import Any
import urllib.error
import urllib.request


DEFAULT_PAYLOAD = {
    "prompt": "Hello, my name is Jane Doe and I need help planning a safe team lunch.",
    "input_scanners": [
        {
            "type": "TokenLimit",
            "params": {
                "limit": 4096,
                "encoding_name": "cl100k_base",
            },
        }
    ],
    "fail_fast": False,
}
DEFAULT_PROMPT = DEFAULT_PAYLOAD["prompt"]
DEFAULT_OUTPUT = "The candidate can review the handbook for general company policies."
DEFAULT_PATHS = {
    "prompt": "/scan/prompt/detailed",
    "output": "/scan/output/detailed",
}


@dataclass(frozen=True)
class RequestResult:
    user_id: int
    request_id: int
    status_code: int | None
    latency_ms: float
    error: str | None = None


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc

    if parsed <= 0 or not math.isfinite(parsed):
        raise argparse.ArgumentTypeError("must be greater than zero")

    return parsed


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc

    if parsed < 0 or not math.isfinite(parsed):
        raise argparse.ArgumentTypeError("must be zero or greater")

    return parsed


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc

    if parsed <= 0 or not math.isfinite(parsed):
        raise argparse.ArgumentTypeError("must be greater than zero")

    return parsed


def non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc

    if parsed < 0 or not math.isfinite(parsed):
        raise argparse.ArgumentTypeError("must be zero or greater")

    return parsed


def target_url(base_url: str, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path

    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def request_path(path: str | None, endpoint: str) -> str:
    if path:
        return path

    return DEFAULT_PATHS[endpoint]


def ramp_delay(user_id: int, users: int, ramp_up_seconds: float) -> float:
    if users == 1 or ramp_up_seconds <= 0:
        return 0.0

    return ramp_up_seconds * ((user_id - 1) / (users - 1))


def percentile(sorted_values: list[float], percentile_value: float) -> float | None:
    if not sorted_values:
        return None

    if len(sorted_values) == 1:
        return sorted_values[0]

    rank = (percentile_value / 100) * (len(sorted_values) - 1)
    lower_index = math.floor(rank)
    upper_index = math.ceil(rank)
    if lower_index == upper_index:
        return sorted_values[lower_index]

    lower = sorted_values[lower_index]
    upper = sorted_values[upper_index]
    return lower + (upper - lower) * (rank - lower_index)


def load_payload(payload_file: Path | None) -> dict[str, Any]:
    if payload_file is None:
        return dict(DEFAULT_PAYLOAD)

    with payload_file.open(encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError("payload file must contain a JSON object")

    return payload


def load_json_file(json_file: Path) -> Any:
    with json_file.open(encoding="utf-8") as file:
        return json.load(file)


def scanner_entries(scanner_config: Any, endpoint: str) -> list[dict[str, Any]]:
    if isinstance(scanner_config, list):
        entries = scanner_config
    elif isinstance(scanner_config, dict) and endpoint == "prompt" and isinstance(
        scanner_config.get("input_scanners"),
        list,
    ):
        entries = scanner_config["input_scanners"]
    elif isinstance(scanner_config, dict) and endpoint == "output" and isinstance(
        scanner_config.get("output_scanners"),
        list,
    ):
        entries = scanner_config["output_scanners"]
    elif isinstance(scanner_config, dict) and isinstance(scanner_config.get("scanners"), list):
        entries = scanner_config["scanners"]
    else:
        raise ValueError(
            "scanner config must be a JSON array, an object with 'scanners', "
            "or an object with endpoint-specific scanner lists"
        )

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("scanner config entries must be JSON objects")

    return entries


def scanner_enabled_for_endpoint(scanner_config: dict[str, Any], endpoint: str) -> bool:
    flag = "useForInput" if endpoint == "prompt" else "useForOutput"
    if flag not in scanner_config:
        return not ("useForInput" in scanner_config or "useForOutput" in scanner_config)

    return bool(scanner_config[flag])


def ban_topics_params(scanner_config: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    topics = scanner_config.get("topics")
    if topics is None:
        return params
    if not isinstance(topics, list):
        raise ValueError("BanTopics 'topics' must be a list")

    topic_names: list[str] = []
    thresholds: set[float] = set()
    for topic in topics:
        if isinstance(topic, str):
            topic_names.append(topic)
            continue
        if not isinstance(topic, dict):
            raise ValueError("BanTopics topics must be strings or objects")

        topic_name = topic.get("topic")
        if not isinstance(topic_name, str) or not topic_name:
            raise ValueError("BanTopics topic objects must include a non-empty 'topic'")
        topic_names.append(topic_name)

        threshold = topic.get("threshold")
        if threshold is not None:
            try:
                thresholds.add(float(threshold))
            except (TypeError, ValueError) as exc:
                raise ValueError("BanTopics topic thresholds must be numbers") from exc

    params["topics"] = topic_names
    if "threshold" not in params and thresholds:
        if len(thresholds) > 1:
            raise ValueError(
                "BanTopics per-topic thresholds differ, but the API supports one "
                "threshold per BanTopics scanner"
            )
        params["threshold"] = thresholds.pop()

    return params


def request_scanner_config(scanner_config: dict[str, Any]) -> dict[str, Any]:
    scanner_type = scanner_config.get("type")
    if not isinstance(scanner_type, str) or not scanner_type:
        raise ValueError("scanner config entries must include a non-empty 'type'")

    raw_params = scanner_config.get("params") or {}
    if not isinstance(raw_params, dict):
        raise ValueError(f"scanner {scanner_type} params must be a JSON object")

    params = dict(raw_params)
    if scanner_type == "BanTopics":
        params = ban_topics_params(scanner_config, params)

    result: dict[str, Any] = {
        "type": scanner_type,
        "params": params,
    }
    if "active" in scanner_config:
        result["active"] = bool(scanner_config["active"])

    return result


def scanner_config_payload(
    *,
    scanner_config: Any,
    endpoint: str,
    prompt: str,
    output: str,
    fail_fast: bool,
) -> dict[str, Any]:
    selected_scanners = [
        request_scanner_config(scanner)
        for scanner in scanner_entries(scanner_config, endpoint)
        if scanner_enabled_for_endpoint(scanner, endpoint)
    ]
    if not selected_scanners:
        raise ValueError(f"scanner config has no scanners enabled for {endpoint}")

    if endpoint == "prompt":
        return {
            "prompt": prompt,
            "input_scanners": selected_scanners,
            "fail_fast": fail_fast,
        }

    return {
        "prompt": prompt,
        "output": output,
        "output_scanners": selected_scanners,
        "fail_fast": fail_fast,
    }


def load_request_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.payload_file:
        return load_payload(args.payload_file)
    if args.scanner_config_file:
        return scanner_config_payload(
            scanner_config=load_json_file(args.scanner_config_file),
            endpoint=args.endpoint,
            prompt=args.prompt,
            output=args.output,
            fail_fast=args.fail_fast,
        )

    if args.endpoint == "prompt":
        payload = dict(DEFAULT_PAYLOAD)
        payload["prompt"] = args.prompt
        payload["fail_fast"] = args.fail_fast
        return payload

    return {
        "prompt": args.prompt,
        "output": args.output,
        "output_scanners": [
            {
                "type": "Gibberish",
                "params": {
                    "threshold": 1,
                    "match_type": "full",
                    "model_max_length": 256,
                },
            }
        ],
        "fail_fast": args.fail_fast,
    }


def encode_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def example_curl(
    *,
    url: str,
    payload: dict[str, Any],
    include_auth: bool,
    timeout_seconds: float,
) -> str:
    lines = [
        "curl -sS \\",
        f"  --max-time {timeout_seconds:g} \\",
        f"  -X POST {shlex.quote(url)} \\",
        f"  -H {shlex.quote('Accept: application/json')} \\",
        f"  -H {shlex.quote('Content-Type: application/json')} \\",
    ]
    if include_auth:
        lines.append('  -H "Authorization: Bearer ${AUTH_TOKEN}" \\')

    body = json.dumps(payload, separators=(",", ":"))
    lines.append(f"  --data-raw {shlex.quote(body)}")
    return "\n".join(lines)


def print_example_curl(
    *,
    url: str,
    payload: dict[str, Any],
    include_auth: bool,
    timeout_seconds: float,
) -> None:
    if include_auth:
        print(
            "example curl request "
            "(bearer token redacted; set AUTH_TOKEN to run it):",
            flush=True,
        )
    else:
        print("example curl request:", flush=True)
    print(
        example_curl(
            url=url,
            payload=payload,
            include_auth=include_auth,
            timeout_seconds=timeout_seconds,
        ),
        flush=True,
    )
    print(flush=True)


def build_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "docker-llm-guard-load-test/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    return headers


def perform_request(
    *,
    url: str,
    data: bytes,
    headers: dict[str, str],
    timeout_seconds: float,
    user_id: int,
    request_id: int,
) -> RequestResult:
    started = time.perf_counter()
    status_code: int | None = None
    error: str | None = None

    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response.read()
            status_code = response.status
            if status_code < 200 or status_code >= 300:
                error = f"HTTP {status_code}"
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        body = exc.read(2048).decode("utf-8", errors="replace").strip()
        error = f"HTTP {status_code}"
        if body:
            error = f"{error}: {body[:300]}"
    except Exception as exc:  # noqa: BLE001 - surface request failures as stats.
        error = f"{type(exc).__name__}: {exc}"

    latency_ms = (time.perf_counter() - started) * 1000
    return RequestResult(
        user_id=user_id,
        request_id=request_id,
        status_code=status_code,
        latency_ms=latency_ms,
        error=error,
    )


async def run_user(
    *,
    user_id: int,
    delay_seconds: float,
    requests_per_user: int,
    url: str,
    data: bytes,
    headers: dict[str, str],
    timeout_seconds: float,
    results: list[RequestResult],
) -> None:
    if delay_seconds > 0:
        await asyncio.sleep(delay_seconds)

    for request_id in range(1, requests_per_user + 1):
        result = await asyncio.to_thread(
            perform_request,
            url=url,
            data=data,
            headers=headers,
            timeout_seconds=timeout_seconds,
            user_id=user_id,
            request_id=request_id,
        )
        results.append(result)


async def progress_reporter(
    *,
    results: list[RequestResult],
    total_requests: int,
    interval_seconds: float,
    started: float,
) -> None:
    if interval_seconds <= 0:
        return

    last_completed = 0
    last_report = started
    while len(results) < total_requests:
        await asyncio.sleep(interval_seconds)
        now = time.perf_counter()
        completed = len(results)
        interval = max(now - last_report, 0.000001)
        current_rps = (completed - last_completed) / interval
        overall_rps = completed / max(now - started, 0.000001)
        print(
            "progress: "
            f"{completed}/{total_requests} requests "
            f"current_rps={current_rps:.2f} overall_rps={overall_rps:.2f}",
            flush=True,
        )
        last_completed = completed
        last_report = now


async def run_warmup_requests(
    *,
    warmup_requests: int,
    url: str,
    data: bytes,
    headers: dict[str, str],
    timeout_seconds: float,
) -> None:
    if warmup_requests <= 0:
        return

    print(f"warming up with {warmup_requests} request(s)...", flush=True)
    for request_id in range(1, warmup_requests + 1):
        result = await asyncio.to_thread(
            perform_request,
            url=url,
            data=data,
            headers=headers,
            timeout_seconds=timeout_seconds,
            user_id=0,
            request_id=request_id,
        )
        if result.error:
            print(f"warmup request {request_id} failed: {result.error}", flush=True)


async def run_load_test(args: argparse.Namespace, payload: dict[str, Any]) -> dict[str, Any]:
    url = target_url(args.base_url, request_path(args.path, args.endpoint))
    data = encode_payload(payload)
    headers = build_headers(args.token)
    total_requests = args.users * args.requests_per_user
    results: list[RequestResult] = []

    if not args.no_curl:
        print_example_curl(
            url=url,
            payload=payload,
            include_auth=bool(args.token),
            timeout_seconds=args.timeout_seconds,
        )

    with ThreadPoolExecutor(max_workers=args.users) as executor:
        asyncio.get_running_loop().set_default_executor(executor)
        await run_warmup_requests(
            warmup_requests=args.warmup_requests,
            url=url,
            data=data,
            headers=headers,
            timeout_seconds=args.timeout_seconds,
        )

        print(
            "starting load test: "
            f"url={url} users={args.users} "
            f"requests_per_user={args.requests_per_user} "
            f"ramp_up_seconds={args.ramp_up_seconds}",
            flush=True,
        )
        started = time.perf_counter()
        user_tasks = [
            asyncio.create_task(
                run_user(
                    user_id=user_id,
                    delay_seconds=ramp_delay(user_id, args.users, args.ramp_up_seconds),
                    requests_per_user=args.requests_per_user,
                    url=url,
                    data=data,
                    headers=headers,
                    timeout_seconds=args.timeout_seconds,
                    results=results,
                )
            )
            for user_id in range(1, args.users + 1)
        ]
        reporter_task = asyncio.create_task(
            progress_reporter(
                results=results,
                total_requests=total_requests,
                interval_seconds=args.progress_interval_seconds,
                started=started,
            )
        )

        await asyncio.gather(*user_tasks)
        ended = time.perf_counter()
        reporter_task.cancel()
        try:
            await reporter_task
        except asyncio.CancelledError:
            pass

    return summarize_results(
        results=results,
        started=started,
        ended=ended,
        url=url,
        users=args.users,
        requests_per_user=args.requests_per_user,
        ramp_up_seconds=args.ramp_up_seconds,
    )


def summarize_results(
    *,
    results: list[RequestResult],
    started: float,
    ended: float,
    url: str,
    users: int,
    requests_per_user: int,
    ramp_up_seconds: float,
) -> dict[str, Any]:
    duration_seconds = max(ended - started, 0.000001)
    sorted_latencies = sorted(result.latency_ms for result in results)
    status_counts = Counter(
        str(result.status_code) if result.status_code is not None else "connection_error"
        for result in results
    )
    error_counts = Counter(result.error for result in results if result.error)
    ok_requests = sum(
        1
        for result in results
        if result.status_code is not None and 200 <= result.status_code < 300
    )
    total_requests = users * requests_per_user

    latency_stats = {
        "min_ms": sorted_latencies[0] if sorted_latencies else None,
        "mean_ms": statistics.fmean(sorted_latencies) if sorted_latencies else None,
        "p50_ms": percentile(sorted_latencies, 50),
        "p90_ms": percentile(sorted_latencies, 90),
        "p95_ms": percentile(sorted_latencies, 95),
        "p99_ms": percentile(sorted_latencies, 99),
        "max_ms": sorted_latencies[-1] if sorted_latencies else None,
    }

    return {
        "url": url,
        "users": users,
        "requests_per_user": requests_per_user,
        "ramp_up_seconds": ramp_up_seconds,
        "planned_requests": total_requests,
        "completed_requests": len(results),
        "ok_requests": ok_requests,
        "failed_requests": len(results) - ok_requests,
        "duration_seconds": duration_seconds,
        "requests_per_second": len(results) / duration_seconds,
        "latency": latency_stats,
        "status_counts": dict(sorted(status_counts.items())),
        "error_counts": dict(error_counts.most_common()),
    }


def format_stat(value: float | None, suffix: str = "") -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}{suffix}"


def print_summary(summary: dict[str, Any]) -> None:
    latency = summary["latency"]
    print("\nload test summary")
    print(f"target: {summary['url']}")
    print(
        "load: "
        f"users={summary['users']} "
        f"requests_per_user={summary['requests_per_user']} "
        f"ramp_up_seconds={summary['ramp_up_seconds']}"
    )
    print(
        "requests: "
        f"planned={summary['planned_requests']} "
        f"completed={summary['completed_requests']} "
        f"ok={summary['ok_requests']} "
        f"failed={summary['failed_requests']}"
    )
    print(f"duration: {summary['duration_seconds']:.2f}s")
    print(f"throughput: {summary['requests_per_second']:.2f} req/s")
    print(
        "latency: "
        f"min={format_stat(latency['min_ms'], 'ms')} "
        f"mean={format_stat(latency['mean_ms'], 'ms')} "
        f"p50={format_stat(latency['p50_ms'], 'ms')} "
        f"p90={format_stat(latency['p90_ms'], 'ms')} "
        f"p95={format_stat(latency['p95_ms'], 'ms')} "
        f"p99={format_stat(latency['p99_ms'], 'ms')} "
        f"max={format_stat(latency['max_ms'], 'ms')}"
    )
    if summary["status_counts"]:
        statuses = ", ".join(
            f"{status}={count}" for status, count in summary["status_counts"].items()
        )
        print(f"statuses: {statuses}")
    if summary["error_counts"]:
        print("errors:")
        for error, count in summary["error_counts"].items():
            print(f"  {count}x {error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a simple load test against docker-llm-guard.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--endpoint",
        choices=("prompt", "output"),
        default="prompt",
        help="Detailed scan endpoint used for the default path and generated payloads.",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("LLM_GUARD_BASE_URL", "http://localhost:8000"),
        help="Base URL for the API. Ignored when --path is a full URL.",
    )
    parser.add_argument(
        "--path",
        help="API path to POST to, or a full URL. Defaults based on --endpoint.",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("AUTH_TOKEN"),
        help="Bearer token. Defaults to the AUTH_TOKEN environment variable.",
    )
    payload_group = parser.add_mutually_exclusive_group()
    payload_group.add_argument(
        "--payload-file",
        type=Path,
        help="JSON request body. Defaults to a lightweight TokenLimit prompt scan.",
    )
    payload_group.add_argument(
        "--scanner-config-file",
        type=Path,
        help="Scanner config JSON to convert into a detailed scan request body.",
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help="Prompt text used when generating a request body.",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="Output text used with --endpoint output when generating a request body.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Set fail_fast=true in generated request bodies.",
    )
    parser.add_argument("--users", type=positive_int, default=10, help="Virtual users.")
    parser.add_argument(
        "--requests-per-user",
        type=positive_int,
        default=10,
        help="Sequential requests each virtual user sends.",
    )
    parser.add_argument(
        "--ramp-up-seconds",
        type=non_negative_float,
        default=0.0,
        help="Seconds over which users are started linearly.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=positive_float,
        default=60.0,
        help="Per-request timeout.",
    )
    parser.add_argument(
        "--progress-interval-seconds",
        type=non_negative_float,
        default=5.0,
        help="Progress report interval. Set to 0 to disable.",
    )
    parser.add_argument(
        "--warmup-requests",
        type=non_negative_int,
        default=0,
        help="Serial warm-up requests to run before timed measurements.",
    )
    parser.add_argument(
        "--stats-json",
        type=Path,
        help="Write the summary stats to this JSON file.",
    )
    parser.add_argument(
        "--fail-on-errors",
        action="store_true",
        help="Exit with status 1 when any measured request fails.",
    )
    parser.add_argument(
        "--no-curl",
        action="store_true",
        help="Do not print the example curl request before the load test.",
    )
    return parser


async def async_main(args: argparse.Namespace) -> dict[str, Any]:
    payload = load_request_payload(args)
    return await run_load_test(args, payload)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        summary = asyncio.run(async_main(args))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"load test setup failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("load test interrupted", file=sys.stderr)
        return 130

    print_summary(summary)
    if args.stats_json:
        try:
            args.stats_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"failed to write stats JSON: {exc}", file=sys.stderr)
            return 2
        print(f"wrote stats: {args.stats_json}")

    if args.fail_on_errors and summary["failed_requests"] > 0:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
