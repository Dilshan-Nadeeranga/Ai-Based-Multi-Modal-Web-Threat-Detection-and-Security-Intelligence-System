"""Checklist 13: dataset_metadata.jsonl persistence."""

from __future__ import annotations

import json

import pytest

from app.exceptions import SampleNotFoundError
from app.services.metadata_service import MetadataStore, read_jsonl


def test_metadata_jsonl_appended_one_object_per_line(dataset_service, dataset_settings, make_request) -> None:
    for _ in range(3):
        dataset_service.add_sample(make_request())
    lines = dataset_settings.dataset_metadata_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert [json.loads(line)["sample_id"] for line in lines] == ["SVT_000001", "SVT_000002", "SVT_000003"]


def test_existing_records_not_overwritten(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request(post_text="first"))
    before = dataset_settings.dataset_metadata_path.read_bytes()
    dataset_service.add_sample(make_request(post_text="second"))
    after = dataset_settings.dataset_metadata_path.read_bytes()
    assert after.startswith(before)
    assert json.loads(after.decode("utf-8").splitlines()[0])["post"]["text"] == "first"


def test_missing_trailing_newline_does_not_merge_lines(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request())
    path = dataset_settings.dataset_metadata_path
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    dataset_service.add_sample(make_request())
    assert len(read_jsonl(path).rows) == 2


def test_empty_and_missing_files(tmp_path) -> None:
    missing = read_jsonl(tmp_path / "none.jsonl")
    assert (missing.exists, missing.rows, missing.issues) == (False, [], [])
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert read_jsonl(empty).rows == []


def test_malformed_lines_reported_not_discarded(tmp_path) -> None:
    path = tmp_path / "m.jsonl"
    path.write_bytes(b'{"sample_id": "SVT_000001"}\nnot json\n[1,2]\n\xff\xfe\n\n{"sample_id": "SVT_000002"}\n')
    result = read_jsonl(path)
    assert [row["sample_id"] for _, row in result.rows] == ["SVT_000001", "SVT_000002"]
    assert [issue.line for issue in result.issues] == [2, 3, 4]


def test_metadata_file_is_valid_utf8_json(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request(post_text="தமிழ் text"))
    raw = dataset_settings.dataset_metadata_path.read_bytes()
    assert json.loads(raw.decode("utf-8"))["post"]["text"] == "தமிழ் text"


def test_get_unknown_sample(dataset_settings) -> None:
    store = MetadataStore(dataset_settings.dataset_metadata_path, dataset_settings.labels_path)
    with pytest.raises(SampleNotFoundError):
        store.get_sample("SVT_000999")
