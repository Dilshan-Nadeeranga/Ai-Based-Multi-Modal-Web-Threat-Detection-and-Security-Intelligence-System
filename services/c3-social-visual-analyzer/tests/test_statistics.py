"""Checklist 14: statistics computed from real metadata records."""

from __future__ import annotations

import json

from app.services.statistics_service import StatisticsService
from tests.conftest import FIXTURES_DIR

LEGIT = FIXTURES_DIR / "sample_legitimate.jpg"
SCAM = FIXTURES_DIR / "sample_scam.jpg"
PAGE2 = FIXTURES_DIR / "sample_post_page2.png"


def _populate(service, make_request) -> None:
    """3 legitimate + 3 scam + 1 undecided synthetic samples with known counts."""
    service.add_sample(make_request(platform="facebook"), [LEGIT])
    service.add_sample(make_request(platform="instagram", embedded_urls=[]), [LEGIT, PAGE2])
    service.add_sample(make_request(platform="facebook", label_status="provisional"))
    service.add_sample(
        make_request(platform="x", is_scam=1, scam_type="phishing",
                     embedded_urls=["https://example.invalid/a", "https://example.invalid/b"]),
        [SCAM],
    )
    service.add_sample(make_request(platform="facebook", is_scam=1, scam_type="brand_impersonation"), [SCAM])
    service.add_sample(make_request(platform="telegram", is_scam=1, scam_type="phishing", embedded_urls=[]))
    service.add_sample(make_request(platform="other", is_scam=None, scam_type="unknown", label_status="needs_review"))


def test_empty_dataset_statistics(dataset_settings) -> None:
    stats = StatisticsService(dataset_settings).generate()
    assert stats.total_samples == 0
    assert stats.binary_labels.model_dump() == {"legitimate": 0, "scam": 0, "undecided": 0, "not_annotated": 0}
    assert stats.misinformation_labels.model_dump() == {"real": 0, "fake": 0, "undecided": 0, "not_annotated": 0}
    assert stats.class_balance.legitimate_percent == 0.0
    assert set(stats.class_distribution.values()) == {0}
    assert stats.total_images == stats.total_embedded_urls == 0
    assert dataset_settings.dataset_statistics_path.is_file()


def test_binary_counts_and_balance(dataset_service, dataset_settings, make_request) -> None:
    _populate(dataset_service, make_request)
    stats = StatisticsService(dataset_settings).compute(include_synthetic=True)
    assert stats.total_samples == 7
    assert stats.binary_labels.model_dump() == {"legitimate": 3, "scam": 3, "undecided": 1, "not_annotated": 0}
    assert stats.class_balance.model_dump() == {"legitimate_percent": 50.0, "scam_percent": 50.0}


def test_scam_class_counts(dataset_service, dataset_settings, make_request) -> None:
    _populate(dataset_service, make_request)
    classes = StatisticsService(dataset_settings).compute(include_synthetic=True).class_distribution
    assert classes == {
        "legitimate": 3, "phishing": 2, "brand_impersonation": 1, "financial_scam": 0, "data_theft": 0,
        "malware": 0, "browser_abuse": 0, "other_scam": 0, "unknown": 1,
    }


def test_platform_counts(dataset_service, dataset_settings, make_request) -> None:
    _populate(dataset_service, make_request)
    platforms = StatisticsService(dataset_settings).compute(include_synthetic=True).platform_distribution
    assert {k: v for k, v in platforms.items() if v} == {
        "facebook": 3, "instagram": 1, "x": 1, "telegram": 1, "other": 1,
    }


def test_image_counts(dataset_service, dataset_settings, make_request) -> None:
    _populate(dataset_service, make_request)
    stats = StatisticsService(dataset_settings).compute(include_synthetic=True)
    assert stats.total_images == 5
    assert (stats.samples_with_images, stats.samples_without_images, stats.samples_with_multiple_images) == (4, 3, 1)


def test_url_counts(dataset_service, dataset_settings, make_request) -> None:
    _populate(dataset_service, make_request)
    stats = StatisticsService(dataset_settings).compute(include_synthetic=True)
    assert stats.total_embedded_urls == 6
    assert (stats.samples_with_urls, stats.samples_without_urls, stats.samples_with_multiple_urls) == (5, 2, 1)
    assert stats.label_status == {"verified": 5, "provisional": 1, "needs_review": 1, "not_annotated": 0}


def test_synthetic_samples_excluded_by_default(dataset_service, dataset_settings, make_request) -> None:
    _populate(dataset_service, make_request)
    dataset_service.add_sample(make_request(collection_method="manual"))
    stats = StatisticsService(dataset_settings).generate()
    assert stats.total_samples == 1
    assert stats.excluded_synthetic_samples == 7
    written = json.loads(dataset_settings.dataset_statistics_path.read_text(encoding="utf-8"))
    assert written["total_samples"] == 1 and written["includes_synthetic"] is False


def test_malformed_and_invalid_lines_counted_not_hidden(dataset_service, dataset_settings, make_request) -> None:
    dataset_service.add_sample(make_request())
    with dataset_settings.dataset_metadata_path.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
        handle.write('{"sample_id": "SVT_000099"}\n')
    stats = StatisticsService(dataset_settings).compute(include_synthetic=True)
    assert (stats.total_samples, stats.malformed_lines, stats.skipped_invalid_records) == (1, 1, 1)
