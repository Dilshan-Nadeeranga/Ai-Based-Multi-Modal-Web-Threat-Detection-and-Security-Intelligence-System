"""One line of ``data/annotations/webpage_captures.jsonl``: a destination capture attempt.

Every attempt is recorded, including failures, so unreachable or blocked URLs
stay visible instead of silently missing. Records are linked to the dataset by
``sample_id`` and ``original_url`` (a URL from the social post).
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.dataset_schema import SCREENSHOTS_PREFIX, _as_utc
from app.services.sample_id_service import SAMPLE_ID_PATTERN
from app.utils.url_utils import normalize_evidence_url

CAPTURE_VERSION = "web-capture-v1"


class CaptureStatus(str, Enum):
    CAPTURED = "captured"
    """Page loaded (HTTP status < 400) and a screenshot was stored."""
    HTTP_ERROR = "http_error"
    """The server answered with HTTP >= 400; the error page was still screenshotted."""
    FAILED = "failed"
    """The page could not be loaded (DNS, connection, TLS, timeout, browser error)."""
    SKIPPED = "skipped"
    """The URL was not opened on purpose (invalid, social-media page, private address)."""


class CaptureErrorCode(str, Enum):
    INVALID_URL = "INVALID_URL"
    SOCIAL_MEDIA_URL = "SOCIAL_MEDIA_URL"
    PRIVATE_ADDRESS = "PRIVATE_ADDRESS"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    NAME_NOT_RESOLVED = "NAME_NOT_RESOLVED"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    TLS_ERROR = "TLS_ERROR"
    TIMEOUT = "TIMEOUT"
    TOO_MANY_REDIRECTS = "TOO_MANY_REDIRECTS"
    DOWNLOAD_BLOCKED = "DOWNLOAD_BLOCKED"
    HTTP_ERROR = "HTTP_ERROR"
    SCREENSHOT_FAILED = "SCREENSHOT_FAILED"
    BROWSER_ERROR = "BROWSER_ERROR"


SKIP_CODES = frozenset({
    CaptureErrorCode.INVALID_URL,
    CaptureErrorCode.SOCIAL_MEDIA_URL,
    CaptureErrorCode.PRIVATE_ADDRESS,
    CaptureErrorCode.UNSUPPORTED_SCHEME,
})


class RedirectHop(BaseModel):
    model_config = ConfigDict(extra="allow")

    url: str
    status: int | None = None


class WebpageCapture(BaseModel):
    model_config = ConfigDict(extra="allow")

    capture_version: str = CAPTURE_VERSION
    sample_id: str
    original_url: str
    requested_url: str | None = None
    status: CaptureStatus
    error_code: CaptureErrorCode | None = None
    error_message: str | None = Field(default=None, max_length=500)
    final_url: str | None = None
    final_domain: str | None = None
    final_registered_domain: str | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    page_title: str | None = None
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    blocked_requests: int = Field(default=0, ge=0)
    screenshot: str | None = None
    screenshot_width: int | None = Field(default=None, gt=0)
    screenshot_height: int | None = Field(default=None, gt=0)
    screenshot_sha256: str | None = None
    screenshot_truncated: bool = False
    browser: str | None = None
    started_at: datetime
    duration_ms: int = Field(ge=0)

    @field_validator("sample_id")
    @classmethod
    def _check_sample_id(cls, value: str) -> str:
        if not SAMPLE_ID_PATTERN.fullmatch(value) or value.endswith("_000000"):
            raise ValueError("sample_id must look like SVT_000001")
        return value

    @field_validator("original_url", "requested_url", "final_url")
    @classmethod
    def _check_url(cls, value: str | None) -> str | None:
        return normalize_evidence_url(value) if value else None

    @field_validator("started_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return _as_utc(value)

    @model_validator(mode="after")
    def _consistent(self) -> "WebpageCapture":
        problems: list[str] = []
        has_page = self.status in (CaptureStatus.CAPTURED, CaptureStatus.HTTP_ERROR)
        if has_page:
            if not self.screenshot or not self.final_url:
                problems.append(f"status '{self.status.value}' requires screenshot and final_url")
            if self.status is CaptureStatus.HTTP_ERROR and (self.http_status is None or self.http_status < 400):
                problems.append("status 'http_error' requires http_status >= 400")
            if self.status is CaptureStatus.CAPTURED and self.http_status is not None and self.http_status >= 400:
                problems.append("status 'captured' requires http_status < 400")
        else:
            if self.error_code is None:
                problems.append(f"status '{self.status.value}' requires error_code")
            if self.screenshot:
                problems.append(f"status '{self.status.value}' must not have a screenshot")
            if self.status is CaptureStatus.SKIPPED and self.error_code not in SKIP_CODES:
                problems.append("status 'skipped' is only for invalid, social-media or private URLs")
        if self.screenshot:
            pattern = rf"^{re.escape(SCREENSHOTS_PREFIX)}{re.escape(self.sample_id)}_web_\d{{2}}\.png$"
            if not re.fullmatch(pattern, self.screenshot):
                problems.append(f"screenshot must be {SCREENSHOTS_PREFIX}{self.sample_id}_web_NN.png")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @property
    def has_screenshot(self) -> bool:
        return self.screenshot is not None
