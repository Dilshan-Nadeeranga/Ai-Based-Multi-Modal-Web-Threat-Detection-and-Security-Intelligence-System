"""Dataset API endpoints (isolated storage, synthetic fixtures only)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.services.image_pipeline import ImagePipeline
from tests.conftest import FIXTURES_DIR, FakeOcrEngine

ENDPOINT = "/api/v1/dataset/samples"


@pytest.fixture
def dataset_client(dataset_settings: Settings) -> TestClient:
    pipeline = ImagePipeline.from_settings(dataset_settings, ocr_engine=FakeOcrEngine())
    return TestClient(create_app(settings=dataset_settings, pipeline=pipeline))


def _form(**overrides) -> dict:
    form = {
        "platform": "facebook",
        "post_text": "Verify your example account immediately",
        "embedded_urls": ["https://example.invalid/login"],
        "is_scam": "1",
        "scam_type": "brand_impersonation",
        "label_status": "verified",
        "claimed_brand": "ExampleBrand",
        "collection_method": "synthetic_test",
    }
    form.update(overrides)
    return form


def _files(*names: str) -> list:
    return [("images", (name, (FIXTURES_DIR / name).read_bytes(), "application/octet-stream")) for name in names]


def test_create_sample_with_images_and_urls(dataset_client: TestClient, dataset_settings: Settings) -> None:
    response = dataset_client.post(
        ENDPOINT,
        data=_form(embedded_urls=["https://example.invalid/a", "https://example.invalid/b"]),
        files=_files("sample_scam.jpg", "sample_post_page2.png"),
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["success"] is True
    assert body["sample_id"] == "SVT_000001"
    assert body["data"] == {
        "platform": "facebook",
        "image_count": 2,
        "url_count": 2,
        "labels": {"is_scam": 1, "scam_type": "brand_impersonation", "label_status": "verified",
                   "is_fake": None, "misinfo_type": "unknown", "misinfo_label_status": "not_annotated"},
    }
    assert body["record"]["post"]["images"] == [
        "data/raw/images/SVT_000001_01.jpg",
        "data/raw/images/SVT_000001_02.png",
    ]
    assert (dataset_settings.raw_images_dir / "SVT_000001_02.png").is_file()


def test_create_text_only_sample_without_files(dataset_client: TestClient) -> None:
    response = dataset_client.post(ENDPOINT, data=_form(embedded_urls=[]))
    assert response.status_code == 201
    assert response.json()["data"]["image_count"] == 0


def test_inconsistent_label_rejected(dataset_client: TestClient) -> None:
    response = dataset_client.post(ENDPOINT, data=_form(is_scam="0", scam_type="phishing"), files=_files("sample_scam.jpg"))
    assert response.status_code == 422
    body = response.json()
    assert body["success"] is False
    assert body["error"]["code"] == "DATASET_VALIDATION_ERROR"
    assert "requires scam_type 'legitimate'" in body["error"]["message"]
    assert "Traceback" not in response.text


def test_invalid_platform_and_image(dataset_client: TestClient) -> None:
    assert dataset_client.post(ENDPOINT, data=_form(platform="myspace")).status_code == 422
    response = dataset_client.post(ENDPOINT, data=_form(), files=_files("not_an_image.jpg"))
    assert response.status_code == 415
    assert response.json()["error"]["code"] == "UNSUPPORTED_IMAGE"


def test_get_sample_and_not_found(dataset_client: TestClient) -> None:
    dataset_client.post(ENDPOINT, data=_form())
    assert dataset_client.get(f"{ENDPOINT}/SVT_000001").json()["sample_id"] == "SVT_000001"
    assert dataset_client.get(f"{ENDPOINT}/SVT_000002").status_code == 404
    assert dataset_client.get(f"{ENDPOINT}/..%2F..%2Fetc").status_code in (400, 404)


def test_statistics_and_classes(dataset_client: TestClient) -> None:
    dataset_client.post(ENDPOINT, data=_form(), files=_files("sample_scam.jpg"))
    real = dataset_client.get("/api/v1/dataset/statistics").json()
    assert real["total_samples"] == 0 and real["excluded_synthetic_samples"] == 1
    demo = dataset_client.get("/api/v1/dataset/statistics", params={"include_synthetic": True}).json()
    assert demo["binary_labels"]["scam"] == 1 and demo["total_images"] == 1

    classes = dataset_client.get("/api/v1/dataset/classes").json()
    assert "brand_impersonation" in classes["scam_type"]
    assert classes["label_status"] == ["verified", "provisional", "needs_review", "not_annotated"]
    assert classes["is_fake"] == {"0": "real", "1": "fake"}
    assert "false_connection" in classes["misinfo_type"]


def test_phase1_endpoints_still_work(dataset_client: TestClient) -> None:
    assert dataset_client.get("/health").json()["status"] == "online"
    response = dataset_client.post(
        "/api/v1/preprocess-image",
        data={"sample_id": "SVT_000001_01"},
        files={"image": ("a.jpg", (FIXTURES_DIR / "sample_legitimate.jpg").read_bytes(), "image/jpeg")},
    )
    assert response.status_code == 200, response.text
    assert "/processed/images/SVT_000001_01_" in response.json()["processed_image"]
