"""Destination web capture for dataset samples.

For each URL of a social post (``post.embedded_urls`` plus links written in
the post text) the service validates the URL, opens it in the isolated
browser, follows redirects, records the final URL, domain and page title,
stores a full-page screenshot as ``data/webpage_screenshots/SVT_xxxxxx_web_NN.png``
and appends one :class:`WebpageCapture` line to ``webpage_captures.jsonl``.

Every attempt is logged, including blocked and unreachable URLs. Sample
records in ``dataset_metadata.jsonl`` stay append-only; :meth:`with_destination`
returns a sample whose ``destination`` section is filled from its captures.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import time
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image, UnidentifiedImageError
from pydantic import ValidationError

from app.config import Settings
from app.exceptions import StorageError, WebCaptureDisabledError
from app.schemas.capture_schema import SKIP_CODES, CaptureErrorCode, CaptureStatus, WebpageCapture
from app.schemas.dataset_schema import DatasetSample, utc_now
from app.services.annotation_service import JsonlWriter
from app.services.browser_capture import PageCaptureResult, PageCapturer, PlaywrightCapturer
from app.services.metadata_service import JsonlReadResult, MetadataStore, read_jsonl
from app.services.sample_id_service import screenshot_filename, validate_dataset_sample_id
from app.services.url_safety import UrlSafetyPolicy
from app.utils.file_lock import FileLock
from app.utils.file_utils import ensure_within_directory, from_dataset_path, to_dataset_path
from app.utils.url_utils import extract_urls, registered_domain, unwrap_link, url_hostname

logger = logging.getLogger(__name__)

CapturerFactory = Callable[[], AbstractContextManager[PageCapturer]]
_SCREENSHOT_NUMBER = re.compile(r"_web_(\d{2})\.png$")


def candidate_urls(sample: DatasetSample) -> list[str]:
    """URLs of the post: embedded URLs first, then links found in the post text."""
    urls: list[str] = []
    for url in [*sample.post.embedded_urls, *extract_urls(sample.post.text)]:
        if url not in urls:
            urls.append(url)
    return urls


@dataclass
class SampleCaptureOutcome:
    sample_id: str
    captures: list[WebpageCapture] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)


class WebCaptureService:
    def __init__(
        self,
        settings: Settings,
        capturer_factory: CapturerFactory | None = None,
        policy: UrlSafetyPolicy | None = None,
        store: MetadataStore | None = None,
    ) -> None:
        self.settings = settings
        self.policy = policy or UrlSafetyPolicy.from_settings(settings)
        self.capturer_factory = capturer_factory or (lambda: PlaywrightCapturer(settings, self.policy))
        self.store = store or MetadataStore(settings.dataset_metadata_path, settings.labels_path)
        self._writer = JsonlWriter(settings.webpage_captures_path)
        settings.ensure_directories()

    # ------------------------------------------------------------------ reading

    def read_captures(self) -> JsonlReadResult:
        return read_jsonl(self.settings.webpage_captures_path)

    def captures_by_sample(self) -> dict[str, list[WebpageCapture]]:
        grouped: dict[str, list[WebpageCapture]] = {}
        for line, row in self.read_captures().rows:
            try:
                capture = WebpageCapture.model_validate(row)
            except ValidationError:
                logger.warning("Skipped invalid capture record at line %d (run validate_dataset.py)", line)
                continue
            grouped.setdefault(capture.sample_id, []).append(capture)
        return grouped

    def load_samples(self) -> list[DatasetSample]:
        """Valid samples of the metadata file, first record per sample_id."""
        samples: dict[str, DatasetSample] = {}
        for line, row in self.store.read_metadata().rows:
            try:
                sample = DatasetSample.model_validate(row)
            except ValidationError:
                logger.warning("Skipped invalid sample record at line %d (run validate_dataset.py)", line)
                continue
            samples.setdefault(sample.sample_id, sample)
        return list(samples.values())

    def captures_for(self, sample_id: str) -> list[WebpageCapture]:
        return self.captures_by_sample().get(validate_dataset_sample_id(sample_id), [])

    @staticmethod
    def with_destination(sample: DatasetSample, captures: Iterable[WebpageCapture]) -> DatasetSample:
        """``sample`` with ``destination``/``processing`` filled from its successful captures."""
        urls = candidate_urls(sample)
        good = [c for c in captures if c.status is CaptureStatus.CAPTURED and c.original_url in urls]
        if not good:
            return sample
        latest = good[-1]
        destination = sample.destination.model_copy(update={
            "original_url": latest.original_url,
            "final_url": latest.final_url,
            "domain": latest.final_domain,
            "registered_domain": latest.final_registered_domain,
            "page_title": latest.page_title,
            "http_status": latest.http_status,
            "captured_at": latest.started_at,
            "screenshots": [c.screenshot for c in good if c.screenshot],
        })
        processing = sample.processing.model_copy(update={"webpage_captured": True})
        return DatasetSample.model_validate(
            sample.model_copy(update={"destination": destination, "processing": processing}).model_dump()
        )

    # ------------------------------------------------------------------ capture

    def capture_samples(
        self,
        sample_ids: Iterable[str],
        *,
        urls: list[str] | None = None,
        recapture: bool = False,
        retry_failed: bool = False,
        delay_seconds: float = 0.0,
        on_capture: Callable[[WebpageCapture], None] | None = None,
    ) -> list[SampleCaptureOutcome]:
        """Capture several samples with one browser process."""
        if not self.settings.web_capture_enabled:
            raise WebCaptureDisabledError()
        samples = [self.store.get_sample(validate_dataset_sample_id(sid)) for sid in sample_ids]
        history = self.captures_by_sample()
        outcomes: list[SampleCaptureOutcome] = []
        plans = [(s, self.plan(s, urls, history.get(s.sample_id, []), recapture, retry_failed)) for s in samples]
        needs_browser = any(
            self.policy.check(unwrap_link(url), resolve=False).allowed for _, (todo, _) in plans for url in todo
        )
        with ExitStack() as stack:
            capturer = stack.enter_context(self.capturer_factory()) if needs_browser else None
            first = True
            for sample, (todo, skipped) in plans:
                outcome = SampleCaptureOutcome(sample.sample_id, skipped=skipped)
                for url in todo:
                    if not first and delay_seconds:
                        time.sleep(delay_seconds)
                    first = False
                    record = self._capture_url(sample.sample_id, url, capturer)
                    outcome.captures.append(record)
                    if on_capture is not None:
                        on_capture(record)
                outcomes.append(outcome)
        return outcomes

    def capture_sample(self, sample_id: str, **options) -> SampleCaptureOutcome:
        return self.capture_samples([sample_id], **options)[0]

    def plan(
        self,
        sample: DatasetSample,
        requested: list[str] | None,
        history: list[WebpageCapture],
        recapture: bool,
        retry_failed: bool,
    ) -> tuple[list[str], list[tuple[str, str]]]:
        available = candidate_urls(sample)
        todo: list[str] = []
        skipped: list[tuple[str, str]] = []
        for url in requested if requested is not None else available:
            if url not in available:
                skipped.append((url, "not a URL of this post"))
                continue
            previous = [c for c in history if c.original_url == url]
            if not recapture and any(c.status is CaptureStatus.CAPTURED for c in previous):
                skipped.append((url, "already captured"))
            elif not recapture and previous and not retry_failed:
                skipped.append((url, f"already attempted ({previous[-1].status.value})"))
            else:
                todo.append(url)
        return todo, skipped

    def _capture_url(self, sample_id: str, original_url: str, capturer: PageCapturer | None) -> WebpageCapture:
        started = utc_now()
        clock = time.monotonic()
        requested = unwrap_link(original_url)
        verdict = self.policy.check(requested)
        if not verdict.allowed or capturer is None:
            code = verdict.code or CaptureErrorCode.BROWSER_ERROR
            return self._append(WebpageCapture(
                sample_id=sample_id,
                original_url=original_url,
                requested_url=requested,
                status=CaptureStatus.SKIPPED if code in SKIP_CODES else CaptureStatus.FAILED,
                error_code=code,
                error_message=(verdict.message or "not opened")[:500],
                started_at=started,
                duration_ms=int((time.monotonic() - clock) * 1000),
            ))

        result = capturer.capture(requested)
        return self._record_result(sample_id, original_url, requested, result, started, clock)

    def _record_result(self, sample_id: str, original_url: str, requested: str, result: PageCaptureResult,
                       started, clock: float) -> WebpageCapture:
        base = {
            "sample_id": sample_id,
            "original_url": original_url,
            "requested_url": requested,
            "redirect_chain": result.redirect_chain,
            "blocked_requests": result.blocked_requests,
            "browser": result.browser,
            "started_at": started,
        }
        if result.png is None or result.final_url is None:
            code = result.error_code or CaptureErrorCode.BROWSER_ERROR
            return self._append(WebpageCapture(
                **base,
                status=CaptureStatus.SKIPPED if code in SKIP_CODES else CaptureStatus.FAILED,
                error_code=code,
                error_message=(result.error_message or "page could not be captured")[:500],
                final_url=result.final_url,
                http_status=result.http_status,
                duration_ms=int((time.monotonic() - clock) * 1000),
            ))
        try:
            with Image.open(io.BytesIO(result.png)) as image:
                image.verify()
            with Image.open(io.BytesIO(result.png)) as image:
                width, height, image_format = image.width, image.height, image.format
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            return self._append(WebpageCapture(
                **base, status=CaptureStatus.FAILED, error_code=CaptureErrorCode.SCREENSHOT_FAILED,
                error_message=f"browser returned an unreadable screenshot: {exc}"[:500],
                final_url=result.final_url, http_status=result.http_status,
                duration_ms=int((time.monotonic() - clock) * 1000),
            ))
        if image_format != "PNG":
            return self._append(WebpageCapture(
                **base, status=CaptureStatus.FAILED, error_code=CaptureErrorCode.SCREENSHOT_FAILED,
                error_message=f"screenshot is {image_format}, expected PNG",
                final_url=result.final_url, http_status=result.http_status,
                duration_ms=int((time.monotonic() - clock) * 1000),
            ))

        host = url_hostname(result.final_url)
        http_error = result.http_status is not None and result.http_status >= 400
        with FileLock(self.settings.dataset_lock_path, timeout_seconds=self.settings.dataset_lock_timeout_seconds):
            path = self._write_screenshot(sample_id, result.png)
            try:
                return self._append(WebpageCapture(
                    **base,
                    status=CaptureStatus.HTTP_ERROR if http_error else CaptureStatus.CAPTURED,
                    error_code=CaptureErrorCode.HTTP_ERROR if http_error else None,
                    error_message=f"server answered HTTP {result.http_status}" if http_error else None,
                    final_url=result.final_url,
                    final_domain=host,
                    final_registered_domain=registered_domain(host),
                    http_status=result.http_status,
                    page_title=result.title,
                    screenshot=to_dataset_path(path, self.settings.data_dir),
                    screenshot_width=width,
                    screenshot_height=height,
                    screenshot_sha256=hashlib.sha256(result.png).hexdigest(),
                    screenshot_truncated=result.truncated,
                    duration_ms=int((time.monotonic() - clock) * 1000),
                ))
            except BaseException:
                path.unlink(missing_ok=True)
                raise

    def _write_screenshot(self, sample_id: str, png: bytes) -> Path:
        directory = self.settings.webpage_screenshots_dir
        used = {int(m.group(1)) for entry in directory.glob(f"{sample_id}_web_*.png")
                if (m := _SCREENSHOT_NUMBER.search(entry.name))}
        for captures in self.captures_by_sample().get(sample_id, []):
            if captures.screenshot and (m := _SCREENSHOT_NUMBER.search(captures.screenshot)):
                used.add(int(m.group(1)))
        number = max(used, default=0) + 1
        if number > 99:
            raise StorageError(f"{sample_id} already has 99 webpage screenshots.")
        path = ensure_within_directory(directory / screenshot_filename(sample_id, number), directory)
        try:
            with path.open("xb") as handle:
                handle.write(png)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            logger.error("Could not store screenshot %s: %s", path.name, exc)
            raise StorageError("Failed to store the webpage screenshot.") from exc
        logger.info("Screenshot stored: %s", path.name)
        return path

    def _append(self, capture: WebpageCapture) -> WebpageCapture:
        self._writer.append(capture.model_dump(mode="json"))
        logger.info("Capture recorded: %s %s -> %s%s", capture.sample_id, capture.original_url,
                    capture.status.value, f" ({capture.error_code.value})" if capture.error_code else "")
        return capture

    def screenshot_path(self, capture: WebpageCapture) -> Path | None:
        return from_dataset_path(capture.screenshot, self.settings.data_dir) if capture.screenshot else None
