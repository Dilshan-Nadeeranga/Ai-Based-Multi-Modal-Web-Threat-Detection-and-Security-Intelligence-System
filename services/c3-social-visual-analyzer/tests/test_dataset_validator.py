"""Dataset validator: file references, duplicates, labels, JSONL integrity."""

from __future__ import annotations

import json

from app.services.dataset_validator import DatasetValidator
from app.utils.file_utils import from_dataset_path
from tests.conftest import FIXTURES_DIR

LEGIT = FIXTURES_DIR / "sample_legitimate.jpg"


def _codes(report) -> set[str]:
    return {finding.code for finding in report.findings}


def _rewrite(path, transform) -> None:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = transform(rows)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_empty_dataset_is_valid_with_warning(dataset_settings) -> None:
    report = DatasetValidator(dataset_settings).validate()
    assert report.valid is True
    assert _codes(report) == {"METADATA_MISSING"}


def test_valid_dataset_and_existing_image_path(dataset_service, dataset_settings, make_request) -> None:
    sample = dataset_service.add_sample(make_request(), [LEGIT])
    image_path = from_dataset_path(sample.post.images[0], dataset_settings.data_dir)
    assert image_path.is_file() and image_path.parent == dataset_settings.raw_images_dir.resolve()

    report = DatasetValidator(dataset_settings).validate()
    assert report.valid is True
    assert report.records_checked == 1 and report.valid_records == 1
    assert _codes(report) == {"SYNTHETIC_SAMPLE"}


def test_missing_image_detected(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request(), [LEGIT])
    (dataset_settings.raw_images_dir / "SVT_000001_01.jpg").unlink()
    report = DatasetValidator(dataset_settings).validate()
    assert report.valid is False
    assert "IMAGE_MISSING" in _codes(report)


def test_duplicate_sample_ids_detected(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request())
    path = dataset_settings.dataset_metadata_path
    path.write_text(path.read_text(encoding="utf-8") * 2, encoding="utf-8")
    report = DatasetValidator(dataset_settings).validate()
    assert report.valid is False
    assert "DUPLICATE_SAMPLE_ID" in _codes(report)


def test_duplicate_image_path_detected(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request(), [LEGIT])
    dataset_service.add_sample(make_request())

    def share_image(rows):
        rows[1]["post"]["images"] = list(rows[0]["post"]["images"])
        return rows

    _rewrite(dataset_settings.dataset_metadata_path, share_image)
    assert "DUPLICATE_IMAGE_PATH" in _codes(DatasetValidator(dataset_settings).validate())


def test_inconsistent_label_and_bad_platform_detected(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request())
    dataset_service.add_sample(make_request())

    def corrupt(rows):
        rows[0]["labels"]["scam_type"] = "phishing"
        rows[1]["source"]["platform"] = "myspace"
        return rows

    _rewrite(dataset_settings.dataset_metadata_path, corrupt)
    report = DatasetValidator(dataset_settings).validate()
    assert {"LABEL_INCONSISTENT", "INVALID_PLATFORM"} <= _codes(report)


def test_invalid_jsonl_and_missing_fields_detected(dataset_settings) -> None:
    dataset_settings.dataset_metadata_path.write_text('{"sample_id": "SVT_000001"}\nnot json\n', encoding="utf-8")
    report = DatasetValidator(dataset_settings).validate()
    assert {"INVALID_JSONL", "REQUIRED_FIELD_MISSING"} <= _codes(report)
    assert report.records_checked == 2


def test_url_must_be_string(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request(embedded_urls=[]))

    def numeric_url(rows):
        rows[0]["post"]["embedded_urls"] = [42]
        return rows

    _rewrite(dataset_settings.dataset_metadata_path, numeric_url)
    assert "INVALID_URL" in _codes(DatasetValidator(dataset_settings).validate())


def test_corrupted_image_content_detected(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request(), [LEGIT])
    (dataset_settings.raw_images_dir / "SVT_000001_01.jpg").write_bytes(b"garbage")
    assert "IMAGE_INVALID" in _codes(DatasetValidator(dataset_settings).validate())
    assert "IMAGE_INVALID" not in _codes(DatasetValidator(dataset_settings, check_image_content=False).validate())


def test_label_log_problems_and_orphans(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request())
    with dataset_settings.labels_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "sample_id": "SVT_000099", "is_scam": 1, "scam_type": "phishing",
            "label_status": "verified", "labelled_at": "2026-10-08T00:00:00Z",
        }) + "\n")
    (dataset_settings.raw_images_dir / "SVT_000077_01.jpg").write_bytes(b"x")
    codes = _codes(DatasetValidator(dataset_settings).validate())
    assert {"LABEL_ORPHAN", "ORPHAN_IMAGE_FILE"} <= codes
