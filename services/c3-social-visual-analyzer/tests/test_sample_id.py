"""Checklist 3: label-independent SVT_000001 sample IDs."""

from __future__ import annotations

import threading

import pytest

from app.exceptions import InvalidDatasetSampleIdError, SampleAlreadyExistsError
from app.services.sample_id_service import (
    format_sample_id,
    ids_used_by_files,
    image_filename,
    next_sample_id,
    parse_sample_number,
    sample_id_from_filename,
    screenshot_filename,
    validate_dataset_sample_id,
)
from tests.conftest import FIXTURES_DIR


def test_format_produces_svt_000001() -> None:
    assert format_sample_id(1) == "SVT_000001"
    assert format_sample_id(999999) == "SVT_999999"
    with pytest.raises(ValueError):
        format_sample_id(0)


def test_next_id_increments() -> None:
    assert next_sample_id([]) == "SVT_000001"
    assert next_sample_id(["SVT_000001"]) == "SVT_000002"
    assert next_sample_id(["SVT_000009", "SVT_000003"]) == "SVT_000010"


def test_gaps_are_never_reused_and_foreign_ids_ignored() -> None:
    assert next_sample_id(["SVT_000001", "SVT_000005", "SCAM_0001", "junk"]) == "SVT_000006"


@pytest.mark.parametrize("bad", ["SCAM_0001", "SVT_1", "SVT_0000001", "svt_000001", "SVT_000000", "../SVT_000001", ""])
def test_invalid_manual_ids_rejected(bad: str) -> None:
    with pytest.raises(InvalidDatasetSampleIdError):
        validate_dataset_sample_id(bad)


def test_parse_and_naming_helpers() -> None:
    assert parse_sample_number(" SVT_000042 ") == 42
    assert image_filename("SVT_000010", 1, ".jpg") == "SVT_000010_01.jpg"
    assert image_filename("SVT_000010", 3, ".png") == "SVT_000010_03.png"
    assert screenshot_filename("SVT_000001", 2) == "SVT_000001_web_02.png"
    assert sample_id_from_filename("SVT_000010_02.jpg") == "SVT_000010"
    assert sample_id_from_filename("SVT_000010.json") == "SVT_000010"
    assert sample_id_from_filename(".staging_abc.jpg") is None


def test_ids_used_by_files(tmp_path) -> None:
    (tmp_path / "SVT_000007_01.jpg").write_bytes(b"x")
    (tmp_path / ".gitkeep").write_bytes(b"")
    assert ids_used_by_files([tmp_path, tmp_path / "missing"]) == {"SVT_000007"}


def test_no_duplicate_ids_from_existing_metadata(dataset_service, make_request) -> None:
    ids = [dataset_service.add_sample(make_request()).sample_id for _ in range(3)]
    assert ids == ["SVT_000001", "SVT_000002", "SVT_000003"]

    from app.services.dataset_service import DatasetService

    fresh_service = DatasetService(dataset_service.settings)
    assert fresh_service.add_sample(make_request()).sample_id == "SVT_000004"


def test_orphan_files_reserve_their_id(dataset_service, dataset_settings, make_request) -> None:
    (dataset_settings.raw_images_dir / "SVT_000005_01.jpg").write_bytes(b"left over")
    assert dataset_service.add_sample(make_request()).sample_id == "SVT_000006"


def test_manual_id_supported_and_duplicates_refused(dataset_service, make_request) -> None:
    assert dataset_service.add_sample(make_request(sample_id="SVT_000050")).sample_id == "SVT_000050"
    with pytest.raises(SampleAlreadyExistsError):
        dataset_service.add_sample(make_request(sample_id="SVT_000050"))
    assert dataset_service.add_sample(make_request()).sample_id == "SVT_000051"


def test_concurrent_adds_get_unique_ids(dataset_service, make_request) -> None:
    created: list[str] = []
    errors: list[Exception] = []

    def worker() -> None:
        try:
            sample = dataset_service.add_sample(make_request(), [FIXTURES_DIR / "sample_legitimate.jpg"])
            created.append(sample.sample_id)
        except Exception as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sorted(created) == [format_sample_id(n) for n in range(1, 9)]
