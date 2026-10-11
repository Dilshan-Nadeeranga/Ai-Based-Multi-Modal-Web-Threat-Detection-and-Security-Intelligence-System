"""Checklist 6 & 12 plus acceptance scenarios A-E at the pipeline level."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from PIL import Image

from app.config import Settings
from app.exceptions import (
    AnnotationStorageError,
    HashDatabaseError,
    OcrEngineUnavailableError,
    SampleAlreadyExistsError,
)
from app.services.annotation_service import AnnotationService
from app.services.image_pipeline import ImagePipeline
from tests.conftest import FakeOcrEngine, make_pattern_image


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_scenario_a_valid_image_full_pipeline(
    pipeline: ImagePipeline, settings: Settings, fake_ocr: FakeOcrEngine, write_image
) -> None:
    source = write_image("screenshot.jpg", make_pattern_image((1920, 1080)))

    result = pipeline.process_post_image(source, "SCAM_0001")

    assert result.status == "success"
    record = result.record
    assert record is not None
    raw_files = list(settings.raw_uploads_dir.iterdir())
    processed_files = list(settings.processed_images_dir.iterdir())
    assert len(raw_files) == 1 and raw_files[0].name.startswith("SCAM_0001_")
    assert raw_files[0].suffix == ".jpg"
    assert len(processed_files) == 1 and processed_files[0].suffix == ".png"
    assert record.original_image == f"data/raw/uploads/{raw_files[0].name}"
    assert record.processed_image == f"data/processed/images/{processed_files[0].name}"

    with Image.open(processed_files[0]) as processed:
        assert processed.mode == "RGB"
        assert processed.size == (1024, 576)

    assert (record.image.original_width, record.image.original_height) == (1920, 1080)
    assert (record.image.processed_width, record.image.processed_height) == (1024, 576)
    assert record.image.normalization.shape == [576, 1024, 3]
    assert record.image.normalization.dtype == "float32"
    assert record.duplicate_detection.is_duplicate is False
    assert record.ocr.text == "SAMPLE TEXT"
    assert record.ocr.average_confidence == 85.0
    assert fake_ocr.calls == [(1920, 1080)]

    hashes = json.loads(settings.image_hashes_path.read_text(encoding="utf-8"))
    assert hashes["SCAM_0001"]["phash"] == record.duplicate_detection.phash
    assert hashes["SCAM_0001"]["file"] == record.processed_image

    lines = _jsonl(settings.ocr_results_path)
    assert len(lines) == 1
    assert lines[0]["sample_id"] == "SCAM_0001"
    assert lines[0]["processing_status"] == "success"
    assert lines[0]["ocr"]["average_confidence"] == 85.0
    assert "array" not in json.dumps(lines[0])


def test_portrait_image_aspect_ratio(pipeline: ImagePipeline, write_image) -> None:
    result = pipeline.process_post_image(write_image("p.png", make_pattern_image((1080, 1920))), "POST_0001")
    assert result.record is not None
    assert (result.record.image.processed_width, result.record.image.processed_height) == (576, 1024)


def test_scenario_b_same_image_uploaded_again(pipeline: ImagePipeline, settings: Settings, write_image) -> None:
    first = pipeline.process_post_image(write_image("a.png"), "SCAM_0001")
    second = pipeline.process_post_image(write_image("b.png"), "SCAM_0020")

    assert first.status == second.status == "success"
    duplicate = second.record.duplicate_detection  # type: ignore[union-attr]
    assert duplicate.is_duplicate is True
    assert duplicate.duplicate_type == "exact_duplicate"
    assert duplicate.matched_sample_id == "SCAM_0001"
    assert duplicate.hash_distance == 0

    lines = _jsonl(settings.ocr_results_path)
    assert [line["sample_id"] for line in lines] == ["SCAM_0001", "SCAM_0020"]
    assert lines[1]["duplicate_detection"]["matched_sample_id"] == "SCAM_0001"
    hashes = json.loads(settings.image_hashes_path.read_text(encoding="utf-8"))
    assert hashes["SCAM_0020"]["duplicate_of"] == "SCAM_0001"
    assert len(list(settings.processed_images_dir.iterdir())) == 2


def test_scenario_c_corrupted_image_rejected(
    pipeline: ImagePipeline, settings: Settings, fake_ocr: FakeOcrEngine, write_image
) -> None:
    path = write_image("broken.jpg", make_pattern_image((800, 600)))
    path.write_bytes(path.read_bytes()[:500])

    result = pipeline.process_post_image(path, "SCAM_0009")

    assert result.status == "rejected"
    assert fake_ocr.calls == []
    assert list(settings.raw_uploads_dir.iterdir()) == []
    assert list(settings.processed_images_dir.iterdir()) == []
    rejected = list(settings.rejected_dir.iterdir())
    assert len(rejected) == 1 and rejected[0].name.startswith("SCAM_0009_")

    lines = _jsonl(settings.rejected_images_path)
    assert lines == [
        {
            "sample_id": "SCAM_0009",
            "status": "rejected",
            "reason": "Corrupted or unreadable image",
            "error_code": "CORRUPTED_IMAGE",
            "stored_path": f"data/rejected/{rejected[0].name}",
            "original_filename": "broken.jpg",
            "file_size_bytes": 500,
            "sha256": lines[0]["sha256"],
            "created_at": lines[0]["created_at"],
        }
    ]
    assert not settings.image_hashes_path.exists()
    assert not settings.ocr_results_path.exists()


def test_scenario_d_rgba_png(pipeline: ImagePipeline, settings: Settings, write_image) -> None:
    rgba = make_pattern_image((600, 400)).convert("RGBA")
    rgba.putalpha(128)
    result = pipeline.process_post_image(write_image("logo.png", rgba), "LEGIT_0001")

    assert result.status == "success"
    assert result.record is not None
    assert result.record.image.original_mode == "RGBA"
    with Image.open(settings.processed_images_dir / Path(result.record.processed_image).name) as processed:
        assert processed.mode == "RGB"
        assert processed.size == (600, 400)


def test_scenario_e_language_warning_recorded(pipeline: ImagePipeline, settings: Settings, write_image) -> None:
    pipeline.process_post_image(write_image("a.png"), "SCAM_0001")
    line = _jsonl(settings.ocr_results_path)[0]
    assert line["ocr"]["used_languages"] == "eng"
    assert "Using eng" in line["ocr"]["warning"]


def test_unsupported_upload_is_quarantined_with_neutral_suffix(
    pipeline: ImagePipeline, settings: Settings, tmp_path: Path
) -> None:
    payload = tmp_path / "malware.exe"
    payload.write_bytes(b"MZ\x90\x00")
    result = pipeline.process_post_image(payload, "SCAM_0002")
    assert result.status == "rejected"
    assert result.validation.error_code == "UNSUPPORTED_EXTENSION"
    stored = list(settings.rejected_dir.iterdir())
    assert len(stored) == 1 and stored[0].suffix == ".upload"


def test_existing_sample_id_is_not_overwritten(pipeline: ImagePipeline, write_image) -> None:
    pipeline.process_post_image(write_image("a.png"), "SCAM_0001")
    with pytest.raises(SampleAlreadyExistsError):
        pipeline.process_post_image(write_image("b.png", make_pattern_image(variant=1)), "SCAM_0001")


def test_ocr_unavailable_does_not_commit_sample(settings: Settings, write_image) -> None:
    pipeline = ImagePipeline.from_settings(settings, ocr_engine=FakeOcrEngine(OcrEngineUnavailableError()))
    with pytest.raises(OcrEngineUnavailableError):
        pipeline.process_post_image(write_image("a.png"), "SCAM_0001")
    assert not settings.image_hashes_path.exists()
    assert not settings.ocr_results_path.exists()
    assert list(settings.processed_images_dir.iterdir()) == []
    assert len(list(settings.raw_uploads_dir.iterdir())) == 1


def test_malformed_hash_database_is_controlled(pipeline: ImagePipeline, settings: Settings, write_image) -> None:
    settings.image_hashes_path.write_text("{broken", encoding="utf-8")
    with pytest.raises(HashDatabaseError):
        pipeline.process_post_image(write_image("a.png"), "SCAM_0001")
    assert settings.image_hashes_path.read_text(encoding="utf-8") == "{broken"


def test_jsonl_appends_and_repairs_missing_newline(settings: Settings, pipeline: ImagePipeline, write_image) -> None:
    settings.ocr_results_path.write_text('{"sample_id": "OLD_0001"}', encoding="utf-8")
    pipeline.process_post_image(write_image("a.png"), "SCAM_0001")
    lines = _jsonl(settings.ocr_results_path)
    assert [line["sample_id"] for line in lines] == ["OLD_0001", "SCAM_0001"]


def test_dataset_reader_flags_malformed_lines(tmp_path: Path) -> None:
    results = tmp_path / "ocr_results.jsonl"
    results.write_text('{"ok": 1}\nnot-json\n', encoding="utf-8")
    service = AnnotationService(results, tmp_path / "rejected.jsonl")
    with pytest.raises(AnnotationStorageError):
        list(service.iter_ocr_results())


def test_dataset_write_failure_rolls_back_hash(settings: Settings, write_image, monkeypatch) -> None:
    pipeline = ImagePipeline.from_settings(settings, ocr_engine=FakeOcrEngine())

    def failing(record):
        raise AnnotationStorageError("Failed to write the annotation dataset.")

    monkeypatch.setattr(pipeline.annotation_service, "save_ocr_result", failing)
    with pytest.raises(AnnotationStorageError):
        pipeline.process_post_image(write_image("a.png"), "SCAM_0001")
    assert json.loads(settings.image_hashes_path.read_text(encoding="utf-8")) == {}
    assert list(settings.processed_images_dir.iterdir()) == []
