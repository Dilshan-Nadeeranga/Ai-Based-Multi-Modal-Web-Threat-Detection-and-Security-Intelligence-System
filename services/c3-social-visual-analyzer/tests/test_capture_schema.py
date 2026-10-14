from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.capture_schema import CaptureErrorCode, CaptureStatus, WebpageCapture

BASE = {"sample_id": "SVT_000001", "original_url": "https://example.com/", "started_at": "2026-10-11T08:00:00Z",
        "duration_ms": 1200}
CAPTURED = {**BASE, "status": "captured", "final_url": "https://www.example.com/", "http_status": 200,
            "screenshot": "data/webpage_screenshots/SVT_000001_web_01.png"}


def test_captured_record() -> None:
    capture = WebpageCapture.model_validate(CAPTURED)
    assert capture.status is CaptureStatus.CAPTURED
    assert capture.started_at.tzinfo is not None


def test_failed_record() -> None:
    capture = WebpageCapture.model_validate({**BASE, "status": "failed", "error_code": "TIMEOUT",
                                             "error_message": "Timeout 30000ms exceeded"})
    assert capture.error_code is CaptureErrorCode.TIMEOUT


@pytest.mark.parametrize("changes", [
    {"screenshot": None},
    {"final_url": None},
    {"http_status": 404},
    {"screenshot": "data/webpage_screenshots/SVT_000002_web_01.png"},
    {"screenshot": "data/raw/images/SVT_000001_01.png"},
    {"screenshot": "data/webpage_screenshots/SVT_000001_web_1.png"},
    {"sample_id": "SVT_000000"},
])
def test_invalid_captured_records(changes: dict) -> None:
    with pytest.raises(ValidationError):
        WebpageCapture.model_validate({**CAPTURED, **changes})


@pytest.mark.parametrize("record", [
    {**BASE, "status": "failed"},
    {**BASE, "status": "skipped", "error_code": "TIMEOUT"},
    {**BASE, "status": "failed", "error_code": "TIMEOUT",
     "screenshot": "data/webpage_screenshots/SVT_000001_web_01.png"},
    {**CAPTURED, "status": "http_error", "http_status": 200, "error_code": "HTTP_ERROR"},
])
def test_inconsistent_status(record: dict) -> None:
    with pytest.raises(ValidationError):
        WebpageCapture.model_validate(record)
