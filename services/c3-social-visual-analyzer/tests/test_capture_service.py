from __future__ import annotations

import json

import pytest

from app.config import Settings
from app.exceptions import SampleNotFoundError, WebCaptureDisabledError
from app.schemas.capture_schema import CaptureErrorCode, CaptureStatus
from app.services.browser_capture import PageCaptureResult
from app.services.capture_service import WebCaptureService, candidate_urls
from app.services.dataset_validator import DatasetValidator
from app.services.statistics_service import StatisticsService
from tests.capture_fakes import FakeCapturer, failure, png, safe_policy


@pytest.fixture
def fake() -> FakeCapturer:
    return FakeCapturer()


@pytest.fixture
def capture_service(dataset_settings: Settings, fake: FakeCapturer) -> WebCaptureService:
    return WebCaptureService(dataset_settings, capturer_factory=lambda: fake, policy=safe_policy())


def _codes(report) -> set[str]:
    return {f.code for f in report.findings}


def test_candidate_urls_include_links_in_text(dataset_service, make_request) -> None:
    sample = dataset_service.add_sample(make_request(
        post_text="Win now at www.prize.example.org/claim or https://example.com",
        embedded_urls=["https://example.com"]))
    assert candidate_urls(sample) == ["https://example.com", "https://www.prize.example.org/claim"]


def test_capture_stores_screenshot_and_links_sample(dataset_service, make_request, capture_service, fake,
                                                     dataset_settings) -> None:
    sample = dataset_service.add_sample(make_request(embedded_urls=["https://example.com/login"]))
    outcome = capture_service.capture_sample(sample.sample_id)

    [capture] = outcome.captures
    assert capture.status is CaptureStatus.CAPTURED
    assert capture.final_url == "https://www.example.com/login"
    assert capture.final_domain == "www.example.com"
    assert capture.final_registered_domain == "example.com"
    assert capture.page_title == "Example Domain"
    assert [hop.status for hop in capture.redirect_chain] == [301, 200]
    assert capture.screenshot == f"data/webpage_screenshots/{sample.sample_id}_web_01.png"
    assert (capture.screenshot_width, capture.screenshot_height) == (1366, 900)
    assert capture_service.screenshot_path(capture).read_bytes() == png()

    lines = dataset_settings.webpage_captures_path.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["sample_id"] == sample.sample_id

    merged = capture_service.with_destination(sample, capture_service.captures_for(sample.sample_id))
    assert merged.destination.original_url == "https://example.com/login"
    assert merged.destination.final_url == "https://www.example.com/login"
    assert merged.destination.domain == "www.example.com"
    assert merged.destination.screenshots == [capture.screenshot]
    assert merged.destination.model_dump()["page_title"] == "Example Domain"
    assert merged.processing.webpage_captured is True
    assert dataset_service.get_sample(sample.sample_id).processing.webpage_captured is False


def test_second_run_skips_captured_and_recapture_adds_a_file(dataset_service, make_request, capture_service,
                                                             fake) -> None:
    sample = dataset_service.add_sample(make_request(embedded_urls=["https://example.com/a"]))
    capture_service.capture_sample(sample.sample_id)
    again = capture_service.capture_sample(sample.sample_id)
    assert again.captures == [] and again.skipped == [("https://example.com/a", "already captured")]

    redo = capture_service.capture_sample(sample.sample_id, recapture=True)
    assert redo.captures[0].screenshot.endswith("_web_02.png")
    assert len(capture_service.with_destination(sample, capture_service.captures_for(sample.sample_id))
               .destination.screenshots) == 2


def test_blocked_urls_are_recorded_without_opening_browser(dataset_service, make_request, capture_service,
                                                          fake) -> None:
    sample = dataset_service.add_sample(make_request(embedded_urls=[
        "https://www.facebook.com/some.page", "http://192.168.1.1/admin", "https://intranet.example.com/",
        "https://gone.example.invalid/"]))
    outcome = capture_service.capture_sample(sample.sample_id)
    by_url = {c.original_url: c for c in outcome.captures}
    assert by_url["https://www.facebook.com/some.page"].status is CaptureStatus.SKIPPED
    assert by_url["https://www.facebook.com/some.page"].error_code is CaptureErrorCode.SOCIAL_MEDIA_URL
    assert by_url["http://192.168.1.1/admin"].error_code is CaptureErrorCode.PRIVATE_ADDRESS
    assert by_url["https://intranet.example.com/"].error_code is CaptureErrorCode.PRIVATE_ADDRESS
    assert by_url["https://gone.example.invalid/"].status is CaptureStatus.FAILED
    assert by_url["https://gone.example.invalid/"].error_code is CaptureErrorCode.NAME_NOT_RESOLVED
    assert fake.opened == [] and not FakeCapturer.instances[-1].entered
    assert capture_service.with_destination(sample, outcome.captures) == sample


def test_facebook_click_tracker_is_unwrapped(dataset_service, make_request, capture_service, fake) -> None:
    wrapped = "https://l.facebook.com/l.php?u=https%3A%2F%2Fshop.example.com%2Fdeal&h=AT1"
    sample = dataset_service.add_sample(make_request(embedded_urls=[wrapped]))
    [capture] = capture_service.capture_sample(sample.sample_id).captures
    assert fake.opened == ["https://shop.example.com/deal"]
    assert capture.original_url == wrapped and capture.requested_url == "https://shop.example.com/deal"
    assert capture.status is CaptureStatus.CAPTURED


def test_unreachable_and_http_errors(dataset_service, make_request, capture_service, fake) -> None:
    fake.results = {
        "https://down.example.com/": failure(CaptureErrorCode.CONNECTION_FAILED, "net::ERR_CONNECTION_REFUSED"),
        "https://missing.example.com/": PageCaptureResult(final_url="https://missing.example.com/",
                                                          http_status=404, title="Not Found", png=png()),
        "https://broken.example.com/": PageCaptureResult(final_url="https://broken.example.com/",
                                                         http_status=200, png=b"not a png"),
    }
    sample = dataset_service.add_sample(make_request(embedded_urls=list(fake.results)))
    outcome = capture_service.capture_sample(sample.sample_id)
    by_url = {c.original_url: c for c in outcome.captures}
    assert by_url["https://down.example.com/"].status is CaptureStatus.FAILED
    assert by_url["https://down.example.com/"].error_code is CaptureErrorCode.CONNECTION_FAILED
    assert by_url["https://missing.example.com/"].status is CaptureStatus.HTTP_ERROR
    assert by_url["https://missing.example.com/"].screenshot.endswith("_web_01.png")
    assert by_url["https://broken.example.com/"].error_code is CaptureErrorCode.SCREENSHOT_FAILED
    assert capture_service.with_destination(sample, outcome.captures).destination.final_url is None

    assert capture_service.capture_sample(sample.sample_id).captures == []
    fake.results.pop("https://down.example.com/")
    retried = capture_service.capture_sample(sample.sample_id, retry_failed=True,
                                             urls=["https://down.example.com/"])
    assert retried.captures[0].status is CaptureStatus.CAPTURED


def test_requested_url_must_belong_to_the_post(dataset_service, make_request, capture_service, fake) -> None:
    sample = dataset_service.add_sample(make_request(embedded_urls=["https://example.com/"]))
    outcome = capture_service.capture_sample(sample.sample_id, urls=["https://other.example.org/"])
    assert outcome.captures == [] and outcome.skipped == [("https://other.example.org/", "not a URL of this post")]
    assert fake.opened == []


def test_unknown_sample_and_disabled(dataset_settings, capture_service) -> None:
    with pytest.raises(SampleNotFoundError):
        capture_service.capture_sample("SVT_009999")
    disabled = Settings(_env_file=None, data_dir=dataset_settings.data_dir, web_capture_enabled=False)
    with pytest.raises(WebCaptureDisabledError):
        WebCaptureService(disabled, capturer_factory=FakeCapturer).capture_sample("SVT_000001")


def test_validator_and_statistics_cover_captures(dataset_service, make_request, capture_service, fake,
                                                 dataset_settings) -> None:
    fake.results = {"https://down.example.com/": failure(CaptureErrorCode.TIMEOUT, "Timeout 30000ms exceeded")}
    sample = dataset_service.add_sample(make_request(embedded_urls=["https://example.com/",
                                                                    "https://down.example.com/"]))
    dataset_service.add_sample(make_request(embedded_urls=["https://example.org/"]))
    captures = capture_service.capture_sample(sample.sample_id).captures
    assert DatasetValidator(dataset_settings).validate().valid

    stats = StatisticsService(dataset_settings).compute(include_synthetic=True).web_captures
    assert (stats.attempts, stats.captured, stats.failed) == (2, 1, 1)
    assert stats.samples_with_screenshot == 1 and stats.samples_with_urls_not_captured == 1
    assert stats.error_codes == {"TIMEOUT": 1} and stats.redirected_captures == 1
    assert StatisticsService(dataset_settings).compute().web_captures.attempts == 0

    shot = capture_service.screenshot_path(captures[0])
    shot.write_bytes(png((10, 10)))
    (dataset_settings.webpage_screenshots_dir / "stray.png").write_bytes(png((5, 5)))
    with dataset_settings.webpage_captures_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({**captures[1].model_dump(mode="json"), "sample_id": "SVT_009999"}) + "\n")
        handle.write(json.dumps({**captures[1].model_dump(mode="json"), "original_url": "https://x.example/"}) + "\n")
        handle.write('{"sample_id": "SVT_000001", "status": "captured"}\n')
    codes = _codes(DatasetValidator(dataset_settings).validate())
    assert {"SCREENSHOT_MODIFIED", "ORPHAN_SCREENSHOT_FILE", "CAPTURE_ORPHAN", "CAPTURE_URL_MISMATCH",
            "INVALID_CAPTURE"} <= codes

    shot.unlink()
    assert "SCREENSHOT_MISSING" in _codes(DatasetValidator(dataset_settings).validate())
