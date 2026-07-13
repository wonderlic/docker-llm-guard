from __future__ import annotations

import time
import unittest
from concurrent.futures import Future
from threading import Thread
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from api.models import (
    DetailedOutputScanRequest,
    DetailedPromptScanRequest,
    ScannerInvocation,
    ScannerResult,
)
from api.routes import (
    scan_output_detailed_events,
    scan_output_detailed_stream,
    scan_prompt_detailed_events,
    scan_prompt_detailed_stream,
    sse_event,
    wait_for_future_with_keep_alive,
)


def invocation(direction: str, scanner_type: str = "TokenLimit") -> ScannerInvocation:
    return ScannerInvocation(
        index=0,
        instance_id=f"{scanner_type}#1",
        direction=direction,
        scanner_type=scanner_type,
        fingerprint="fingerprint",
        cache_hit=True,
        scanner=SimpleNamespace(),
        lock=SimpleNamespace(),
    )


def scanner_result(scanner_type: str = "TokenLimit") -> ScannerResult:
    return ScannerResult(
        index=0,
        instance_id=f"{scanner_type}#1",
        type=scanner_type,
        config_fingerprint="fingerprint",
        cache_hit=True,
        is_valid=True,
        risk_score=0.0,
        changed=False,
    )


class SseRouteTests(unittest.TestCase):
    def test_sse_event_formats_json_payload(self) -> None:
        event = sse_event("progress", {"scanner_count": 1})

        self.assertEqual(event, 'event: progress\ndata: {"scanner_count":1}\n\n')

    def test_wait_for_future_emits_progress_until_complete(self) -> None:
        future: Future[str] = Future()
        thread = Thread(target=lambda: (time.sleep(0.03), future.set_result("done")))
        thread.start()

        events = list(
            wait_for_future_with_keep_alive(
                future,
                {"current": 1, "total": 2, "remaining": 1},
                interval_seconds=0.01,
            )
        )
        thread.join()

        self.assertGreaterEqual(len(events), 1)
        self.assertTrue(
            all(
                event == 'event: progress\ndata: {"current":1,"total":2,"remaining":1}\n\n'
                for event in events
            )
        )

    def test_prompt_scan_streams_progress_and_complete_response(self) -> None:
        request = DetailedPromptScanRequest(
            prompt="hello",
            input_scanners=[{"type": "TokenLimit"}],
        )

        with patch(
            "api.routes.scan_input_scanner",
            return_value=("hello", scanner_result()),
        ):
            events = list(
                scan_prompt_detailed_events(
                    request,
                    [invocation("input")],
                    "request-fingerprint",
                )
            )

        self.assertIn('event: start\ndata: {"scanner_count":1,"direction":"input"}\n\n', events)
        self.assertTrue(events[1].startswith("event: progress\n"))
        self.assertIn('"status":"queued"', events[1])
        self.assertIn('"current":1', events[1])
        self.assertIn('"total":1', events[1])
        self.assertIn('"remaining":1', events[1])
        self.assertTrue(any(event.startswith("event: scanner_start\n") for event in events))
        self.assertIn('"status":"running"', events[2])
        self.assertIn('"remaining":0', events[2])
        self.assertTrue(any(event.startswith("event: scanner_complete\n") for event in events))
        complete_event = events[-1]
        self.assertTrue(complete_event.startswith("event: complete\n"))
        self.assertIn('"sanitized_prompt":"hello"', complete_event)
        self.assertIn('"config_fingerprint":"request-fingerprint"', complete_event)

    def test_output_scan_streams_progress_and_complete_response(self) -> None:
        request = DetailedOutputScanRequest(
            prompt="hello",
            output="world",
            output_scanners=[{"type": "TokenLimit"}],
        )

        with patch(
            "api.routes.scan_output_scanner",
            return_value=("world", scanner_result()),
        ):
            events = list(
                scan_output_detailed_events(
                    request,
                    [invocation("output")],
                    "request-fingerprint",
                )
            )

        self.assertIn('event: start\ndata: {"scanner_count":1,"direction":"output"}\n\n', events)
        self.assertTrue(events[1].startswith("event: progress\n"))
        self.assertIn('"status":"queued"', events[1])
        self.assertIn('"current":1', events[1])
        self.assertIn('"total":1', events[1])
        self.assertIn('"remaining":1', events[1])
        self.assertTrue(any(event.startswith("event: scanner_start\n") for event in events))
        self.assertIn('"status":"running"', events[2])
        self.assertIn('"remaining":0', events[2])
        self.assertTrue(any(event.startswith("event: scanner_complete\n") for event in events))
        complete_event = events[-1]
        self.assertTrue(complete_event.startswith("event: complete\n"))
        self.assertIn('"sanitized_output":"world"', complete_event)
        self.assertIn('"config_fingerprint":"request-fingerprint"', complete_event)

    def test_prompt_stream_rejects_empty_scanners_before_creating_response(self) -> None:
        request = DetailedPromptScanRequest(prompt="hello", input_scanners=[])

        with patch("api.routes.streaming_scan_response") as streaming_scan_response:
            with self.assertRaises(HTTPException) as raised:
                scan_prompt_detailed_stream(request)

        self.assertEqual(raised.exception.status_code, 422)
        streaming_scan_response.assert_not_called()

    def test_output_stream_rejects_empty_scanners_before_creating_response(self) -> None:
        request = DetailedOutputScanRequest(prompt="hello", output="world", output_scanners=[])

        with patch("api.routes.streaming_scan_response") as streaming_scan_response:
            with self.assertRaises(HTTPException) as raised:
                scan_output_detailed_stream(request)

        self.assertEqual(raised.exception.status_code, 422)
        streaming_scan_response.assert_not_called()

    def test_scanner_preparation_failure_happens_before_creating_response(self) -> None:
        request = DetailedPromptScanRequest(
            prompt="hello",
            input_scanners=[{"type": "Unsupported"}],
        )
        preparation_error = HTTPException(status_code=422, detail="Unsupported scanner")

        with (
            patch("api.routes.active_scanner_configs", return_value=request.input_scanners),
            patch("api.routes.scanner_invocations", side_effect=preparation_error),
            patch("api.routes.streaming_scan_response") as streaming_scan_response,
        ):
            with self.assertRaises(HTTPException) as raised:
                scan_prompt_detailed_stream(request)

        self.assertIs(raised.exception, preparation_error)
        streaming_scan_response.assert_not_called()


if __name__ == "__main__":
    unittest.main()
