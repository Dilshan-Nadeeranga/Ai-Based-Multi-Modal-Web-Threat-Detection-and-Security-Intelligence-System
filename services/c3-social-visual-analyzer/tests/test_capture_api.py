"""Web capture endpoints with a fake browser (no network)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.schemas.capture_schema import CaptureErrorCode
from app.services.capture_service import WebCaptureService
from app.services.image_pipeline import ImagePipeline
from tests.capture_fakes import FakeCapturer, failure, safe_policy
from tests.conftest import FakeOcrEngine


@pytest.fixture
def fake() -> FakeCapturer:
    return FakeCapturer({"https://down.example.com/": failure(CaptureErrorCode.TIMEOUT, "Timeout 30000ms exceeded")})


def _client(settings: Settings, fake: FakeCapturer) -> TestClient:
    pipeline = ImagePipeline.from_settings(settings, ocr_engine=FakeOcrEngine())
    service = WebCaptureService(settings, capturer_factory=lambda: fake, policy=safe_policy())
    return TestClient(create_app(settings=settings, pipeline=pipeline, capture_service=service))


@pytest.fixture
def client(dataset_settings: Settings, fake: FakeCapturer) -> TestClient:
    return _client(dataset_settings, fake)


def test_capture_and_read_back(client, dataset_service, make_request) -> None:
    sample = dataset_service.add_sample(make_request(
        embedded_urls=["https://example.com/", "https://down.example.com/"]))
    response = client.post(f"/api/v1/dataset/samples/{sample.sample_id}/capture", json={})
    assert response.status_code == 200
    body = response.json()
    assert [c["status"] for c in body["captures"]] == ["captured", "failed"]
    assert body["captures"][1]["error_code"] == "TIMEOUT"
    assert body["destination"]["final_url"] == "https://www.example.com/"
    assert body["destination"]["screenshots"] == [f"data/webpage_screenshots/{sample.sample_id}_web_01.png"]

    history = client.get(f"/api/v1/dataset/samples/{sample.sample_id}/captures").json()
    assert len(history["captures"]) == 2
    record = client.get(f"/api/v1/dataset/samples/{sample.sample_id}").json()
    assert record["destination"]["domain"] == "www.example.com"
    assert record["destination"]["page_title"] == "Example Domain"
    assert record["processing"]["webpage_captured"] is True

    again = client.post(f"/api/v1/dataset/samples/{sample.sample_id}/capture").json()
    assert again["captures"] == []
    assert {s["reason"] for s in again["skipped"]} == {"already captured", "already attempted (failed)"}


def test_capture_unknown_sample(client) -> None:
    response = client.post("/api/v1/dataset/samples/SVT_009999/capture", json={})
    assert response.status_code == 404
    assert response.json()["success"] is False
    assert client.get("/api/v1/dataset/samples/SVT_009999/captures").status_code == 404


def test_capture_disabled(dataset_settings, fake, dataset_service, make_request) -> None:
    sample = dataset_service.add_sample(make_request())
    disabled = dataset_settings.model_copy(update={"web_capture_enabled": False})
    response = _client(disabled, fake).post(f"/api/v1/dataset/samples/{sample.sample_id}/capture", json={})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "WEB_CAPTURE_DISABLED"
    assert "Traceback" not in response.text
