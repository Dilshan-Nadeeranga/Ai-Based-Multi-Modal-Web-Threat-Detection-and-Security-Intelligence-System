"""API tests for /health and POST /api/v1/preprocess-image."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.config import Settings
from app.exceptions import OcrEngineUnavailableError
from app.main import create_app
from app.services.image_pipeline import ImagePipeline
from tests.conftest import FakeOcrEngine, image_bytes, make_pattern_image

ENDPOINT = "/api/v1/preprocess-image"


def _upload(client: TestClient, sample_id: str, filename: str, content: bytes, mime: str = "image/png"):
    return client.post(ENDPOINT, data={"sample_id": sample_id}, files={"image": (filename, content, mime)})


def _assert_no_internal_details(response, settings: Settings) -> None:
    text = response.text
    assert "Traceback" not in text
    assert str(settings.data_dir) not in text
    assert str(settings.data_dir).replace("\\", "/") not in text


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "online",
        "service": "social-visual-analyzer",
        "phase": "Phase 1 - OCR and Image Preprocessing",
    }


def test_preprocess_valid_upload(client: TestClient, settings: Settings) -> None:
    content = image_bytes(make_pattern_image((1920, 1080)), "JPEG", quality=90)
    response = _upload(client, "SCAM_0001", "paypal_scam.jpg", content, "image/jpeg")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["success"] is True
    assert body["sample_id"] == "SCAM_0001"
    assert body["status"] == "success"
    assert body["validation"] == {"valid": True, "error": None}
    assert body["image"] == {
        "original_format": "JPEG",
        "original_width": 1920,
        "original_height": 1080,
        "processed_width": 1024,
        "processed_height": 576,
        "color_mode": "RGB",
    }
    assert body["duplicate_detection"]["is_duplicate"] is False
    assert body["duplicate_detection"]["algorithm"] == "phash"
    assert len(body["duplicate_detection"]["phash"]) == 16
    assert body["ocr"]["text"] == "SAMPLE TEXT"
    assert body["ocr"]["average_confidence"] == 85.0
    assert body["processed_image"].startswith("data/processed/images/SCAM_0001_")
    assert body["original_image"].startswith("data/raw/uploads/SCAM_0001_")
    _assert_no_internal_details(response, settings)

    assert settings.ocr_results_path.exists()
    assert "SCAM_0001" in json.loads(settings.image_hashes_path.read_text(encoding="utf-8"))


def test_preprocess_duplicate_is_not_an_error(client: TestClient) -> None:
    content = image_bytes(make_pattern_image(), "PNG")
    assert _upload(client, "SCAM_0001", "a.png", content).status_code == 200

    response = _upload(client, "SCAM_0020", "b.png", content)

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["duplicate_detection"]["is_duplicate"] is True
    assert body["duplicate_detection"]["duplicate_type"] == "exact_duplicate"
    assert body["duplicate_detection"]["matched_sample_id"] == "SCAM_0001"
    assert body["duplicate_detection"]["hash_distance"] == 0


def test_preprocess_rejects_invalid_file(client: TestClient, settings: Settings) -> None:
    response = _upload(client, "SCAM_0021", "corrupt.jpg", b"\xff\xd8\xff\xe0 not really a jpeg", "image/jpeg")

    assert response.status_code == 422
    assert response.json() == {
        "success": False,
        "sample_id": "SCAM_0021",
        "status": "rejected",
        "error": {
            "code": "INVALID_IMAGE",
            "message": "Uploaded file is corrupted or is not a supported image: Corrupted or unreadable image.",
            "reason": "CORRUPTED_IMAGE",
        },
    }
    _assert_no_internal_details(response, settings)
    assert len(list(settings.rejected_dir.iterdir())) == 1


def test_preprocess_rejects_unsupported_extension(client: TestClient) -> None:
    response = _upload(client, "SCAM_0022", "script.exe", b"MZ\x90\x00", "application/octet-stream")
    assert response.status_code == 415
    assert response.json()["error"]["reason"] == "UNSUPPORTED_EXTENSION"


def test_preprocess_rejects_unsupported_actual_format(client: TestClient) -> None:
    gif = image_bytes(make_pattern_image(), "GIF")
    response = _upload(client, "SCAM_0023", "looks_fine.png", gif)
    assert response.status_code == 415
    assert response.json()["error"]["reason"] == "UNSUPPORTED_FORMAT"


def test_preprocess_rejects_empty_file(client: TestClient) -> None:
    response = _upload(client, "SCAM_0024", "empty.png", b"")
    assert response.status_code == 422
    assert response.json()["error"]["reason"] == "EMPTY_FILE"


def test_preprocess_rejects_oversized_file(tmp_path) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path / "data", max_image_size_mb=0.01)
    pipeline = ImagePipeline.from_settings(settings, ocr_engine=FakeOcrEngine())
    client = TestClient(create_app(settings=settings, pipeline=pipeline))

    response = _upload(client, "SCAM_0025", "huge.png", b"\x89PNG" + b"0" * 20_000)

    assert response.status_code == 413
    assert response.json()["error"]["reason"] == "FILE_TOO_LARGE"
    record = json.loads(settings.rejected_images_path.read_text(encoding="utf-8").strip())
    assert record["error_code"] == "FILE_TOO_LARGE" and record["stored_path"] is None


def test_preprocess_rejects_unsafe_sample_id(client: TestClient, settings: Settings) -> None:
    content = image_bytes(make_pattern_image(), "PNG")
    response = _upload(client, "../../../etc/passwd", "a.png", content)
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "INVALID_SAMPLE_ID"
    assert body["sample_id"] is None
    assert list(settings.raw_uploads_dir.iterdir()) == []


def test_preprocess_missing_image_field(client: TestClient) -> None:
    response = client.post(ENDPOINT, data={"sample_id": "SCAM_0001"})
    assert response.status_code == 422
    assert response.json()["error"] == {
        "code": "INVALID_REQUEST",
        "message": "Missing required field(s): image.",
        "reason": None,
    }


def test_preprocess_existing_sample_id_conflict(client: TestClient) -> None:
    content = image_bytes(make_pattern_image(), "PNG")
    assert _upload(client, "SCAM_0001", "a.png", content).status_code == 200
    response = _upload(client, "SCAM_0001", "a.png", content)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SAMPLE_ID_EXISTS"


def test_preprocess_tesseract_unavailable(tmp_path) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path / "data")
    pipeline = ImagePipeline.from_settings(settings, ocr_engine=FakeOcrEngine(OcrEngineUnavailableError()))
    client = TestClient(create_app(settings=settings, pipeline=pipeline))

    response = _upload(client, "SCAM_0001", "a.png", image_bytes(make_pattern_image(), "PNG"))

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "OCR_ENGINE_UNAVAILABLE"
    _assert_no_internal_details(response, settings)


def test_preprocess_malformed_hash_database(client: TestClient, settings: Settings) -> None:
    settings.image_hashes_path.write_text("[not, valid", encoding="utf-8")
    response = _upload(client, "SCAM_0001", "a.png", image_bytes(make_pattern_image(), "PNG"))
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "HASH_DATABASE_ERROR"
    _assert_no_internal_details(response, settings)
