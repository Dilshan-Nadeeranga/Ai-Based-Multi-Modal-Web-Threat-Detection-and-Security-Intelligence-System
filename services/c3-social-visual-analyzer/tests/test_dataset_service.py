"""Checklist 5-12: directories, sample import and text + image + URL linking."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from app.config import Settings
from app.exceptions import (
    AnnotationStorageError,
    DatasetValidationError,
    SourceImageNotFoundError,
    SyntheticSampleNotAllowedError,
    UnsupportedImageError,
)
from app.services.dataset_service import DatasetService, ImageUpload
from tests.conftest import FIXTURES_DIR

LEGIT = FIXTURES_DIR / "sample_legitimate.jpg"
SCAM = FIXTURES_DIR / "sample_scam.jpg"
PAGE2 = FIXTURES_DIR / "sample_post_page2.png"
PAGE3 = FIXTURES_DIR / "sample_post_page3.webp"
NOT_IMAGE = FIXTURES_DIR / "not_an_image.jpg"


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_dataset_directories_created_when_absent(tmp_path: Path) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path / "fresh" / "data")
    assert not settings.data_dir.exists()
    DatasetService(settings)
    for directory in (
        settings.raw_dir,
        settings.raw_images_dir,
        settings.raw_posts_dir,
        settings.processed_dir,
        settings.processed_images_dir,
        settings.webpage_screenshots_dir,
        settings.annotations_dir,
        settings.statistics_dir,
    ):
        assert directory.is_dir(), directory


def test_scenario_a_legitimate_sample_linked(dataset_service, dataset_settings, make_request) -> None:
    sample = dataset_service.add_sample(
        make_request(post_text="Example security information", embedded_urls=["https://example.com"]),
        [LEGIT],
    )

    assert sample.sample_id == "SVT_000001"
    assert sample.post.text == "Example security information"
    assert sample.post.images == ["data/raw/images/SVT_000001_01.jpg"]
    assert sample.post.embedded_urls == ["https://example.com"]
    assert sample.destination.original_url == "https://example.com"
    assert int(sample.labels.is_scam) == 0 and sample.labels.scam_type.value == "legitimate"

    stored = dataset_settings.raw_images_dir / "SVT_000001_01.jpg"
    assert stored.read_bytes() == LEGIT.read_bytes(), "raw evidence must be stored unchanged"

    [record] = _lines(dataset_settings.dataset_metadata_path)
    assert record["sample_id"] == "SVT_000001"
    assert record["post"]["text"] == "Example security information"
    assert record["post"]["images"] == ["data/raw/images/SVT_000001_01.jpg"]
    assert record["post"]["embedded_urls"] == ["https://example.com"]
    assert record["labels"]["is_scam"] == 0
    assert record["post"]["raw_snapshot"] == "data/raw/posts/SVT_000001.json"


def test_scenario_b_scam_sample(dataset_service, dataset_settings, make_request) -> None:
    sample = dataset_service.add_sample(
        make_request(
            post_text="Verify your example account immediately",
            embedded_urls=["https://example.invalid/login"],
            is_scam=1,
            scam_type="brand_impersonation",
            claimed_brand="ExampleBrand",
        ),
        [SCAM],
    )
    assert sample.labels.scam_type.value == "brand_impersonation"
    assert sample.brand.claimed_brand == "ExampleBrand"
    [event] = _lines(dataset_settings.labels_path)
    assert event["sample_id"] == sample.sample_id
    assert (event["is_scam"], event["scam_type"], event["label_status"]) == (1, "brand_impersonation", "verified")


def test_scenario_c_multiple_images(dataset_service, dataset_settings, make_request) -> None:
    sample = dataset_service.add_sample(make_request(sample_id="SVT_000010"), [LEGIT, PAGE2, PAGE3])
    assert sample.post.images == [
        "data/raw/images/SVT_000010_01.jpg",
        "data/raw/images/SVT_000010_02.png",
        "data/raw/images/SVT_000010_03.webp",
    ]
    assert sorted(p.name for p in dataset_settings.raw_images_dir.glob("SVT_000010_*")) == [
        "SVT_000010_01.jpg",
        "SVT_000010_02.png",
        "SVT_000010_03.webp",
    ]


def test_multiple_urls(dataset_service, make_request) -> None:
    sample = dataset_service.add_sample(
        make_request(embedded_urls=["https://example-one.com", "https://example-two.com", "https://example-one.com"])
    )
    assert sample.post.embedded_urls == ["https://example-one.com", "https://example-two.com"]


def test_urls_given_as_one_multiline_string(dataset_service, make_request) -> None:
    sample = dataset_service.add_sample(make_request(embedded_urls="https://a.example.com\nhttps://b.example.com"))
    assert sample.post.embedded_urls == ["https://a.example.com", "https://b.example.com"]


def test_scenario_d_no_url(dataset_service, make_request) -> None:
    sample = dataset_service.add_sample(make_request(embedded_urls=[]), [LEGIT])
    assert sample.post.embedded_urls == []
    assert sample.destination.original_url is None


def test_scenario_e_text_only(dataset_service, make_request) -> None:
    sample = dataset_service.add_sample(make_request())
    assert sample.post.images == [] and sample.post.text


def test_empty_post_rejected(dataset_service, dataset_settings, make_request) -> None:
    with pytest.raises(DatasetValidationError, match="text and/or at least one image"):
        dataset_service.add_sample(make_request(post_text="   ", embedded_urls=["https://example.com"]))
    assert not dataset_settings.dataset_metadata_path.exists()


def test_scenario_f_invalid_label(dataset_service, dataset_settings, make_request) -> None:
    with pytest.raises(DatasetValidationError) as excinfo:
        dataset_service.add_sample(make_request(is_scam=0, scam_type="phishing"), [LEGIT])
    assert "is_scam=0 (legitimate) requires scam_type 'legitimate'" in excinfo.value.message
    assert list(dataset_settings.raw_images_dir.iterdir()) == []
    assert not dataset_settings.dataset_metadata_path.exists()


@pytest.mark.parametrize(
    "overrides",
    [{"platform": "myspace"}, {"scam_type": "paypal"}, {"label_status": "maybe"}, {"is_scam": 3}],
)
def test_invalid_vocabulary_rejected(make_request, overrides) -> None:
    with pytest.raises(DatasetValidationError):
        make_request(**overrides)


def test_malformed_url_rejected(dataset_service, make_request) -> None:
    with pytest.raises(DatasetValidationError, match="Malformed embedded URL"):
        dataset_service.add_sample(make_request(embedded_urls=["example.com/no-scheme"]))


def test_needs_review_sample_allowed(dataset_service, make_request) -> None:
    sample = dataset_service.add_sample(make_request(is_scam=None, scam_type="unknown", label_status="needs_review"))
    assert sample.labels.is_scam is None


def test_synthetic_refused_without_opt_in(tmp_path: Path, make_request) -> None:
    service = DatasetService(Settings(_env_file=None, data_dir=tmp_path / "data"))
    with pytest.raises(SyntheticSampleNotAllowedError):
        service.add_sample(make_request())
    assert service.add_sample(make_request(collection_method="manual")).sample_id == "SVT_000001"


def test_missing_source_image(dataset_service, make_request, tmp_path: Path) -> None:
    with pytest.raises(SourceImageNotFoundError):
        dataset_service.add_sample(make_request(), [tmp_path / "missing.jpg"])


def test_unsupported_image_rejected_and_rolled_back(dataset_service, dataset_settings, make_request) -> None:
    with pytest.raises(UnsupportedImageError):
        dataset_service.add_sample(make_request(), [LEGIT, NOT_IMAGE])
    assert list(dataset_settings.raw_images_dir.iterdir()) == []
    assert list(dataset_settings.raw_posts_dir.iterdir()) == []
    assert not dataset_settings.dataset_metadata_path.exists()


def test_extension_follows_actual_format(dataset_service, make_request) -> None:
    upload = ImageUpload(io.BytesIO(PAGE2.read_bytes()), "looks_like.jpg")
    sample = dataset_service.add_sample(make_request(), [upload])
    assert sample.post.images == ["data/raw/images/SVT_000001_01.png"]


def test_client_filename_cannot_escape(dataset_service, dataset_settings, make_request) -> None:
    upload = ImageUpload(io.BytesIO(LEGIT.read_bytes()), "../../../etc/evil.jpg")
    sample = dataset_service.add_sample(make_request(), [upload])
    assert sample.post.images == ["data/raw/images/SVT_000001_01.jpg"]
    snapshot = json.loads((dataset_settings.raw_posts_dir / "SVT_000001.json").read_text(encoding="utf-8"))
    assert snapshot["images"][0]["original_filename"] == "evil.jpg"
    assert len(snapshot["images"][0]["sha256"]) == 64


def test_too_many_images_rejected(tmp_path: Path, make_request) -> None:
    settings = Settings(_env_file=None, data_dir=tmp_path / "d", dataset_allow_synthetic=True,
                        dataset_max_images_per_sample=2)
    with pytest.raises(DatasetValidationError, match="At most 2 images"):
        DatasetService(settings).add_sample(make_request(), [LEGIT, SCAM, PAGE2])


def test_malformed_metadata_blocks_new_samples(dataset_service, dataset_settings, make_request) -> None:
    dataset_settings.dataset_metadata_path.write_text('{"sample_id": "SVT_000001"}\n{broken\n', encoding="utf-8")
    with pytest.raises(AnnotationStorageError, match="line 2"):
        dataset_service.add_sample(make_request())
    assert dataset_settings.dataset_metadata_path.read_text(encoding="utf-8").endswith("{broken\n")


def test_sinhala_tamil_text_preserved(dataset_service, dataset_settings, make_request) -> None:
    text = "ඔබගේ ගිණුම තහවුරු කරන්න | உங்கள் கணக்கை சரிபார்க்கவும்"
    dataset_service.add_sample(make_request(post_text=text))
    [record] = _lines(dataset_settings.dataset_metadata_path)
    assert record["post"]["text"] == text
    assert text in dataset_settings.dataset_metadata_path.read_text(encoding="utf-8")


def test_get_sample(dataset_service, make_request) -> None:
    created = dataset_service.add_sample(make_request(), [LEGIT])
    assert dataset_service.get_sample("SVT_000001") == created
