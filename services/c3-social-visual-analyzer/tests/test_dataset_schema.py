"""Checklist 1, 2, 4: dataset classes, labels and the sample JSON schema."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.dataset_classes import (
    SCAM_CATEGORIES,
    CollectionMethod,
    IsFake,
    IsScam,
    LabelStatus,
    MisinfoType,
    Platform,
    ScamType,
    allowed_classes,
    check_label_consistency,
    check_misinformation_consistency,
)
from app.schemas.dataset_schema import DatasetSample, LabelInfo

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)


def _record(**overrides) -> dict:
    record = {
        "sample_id": "SVT_000001",
        "dataset_version": "0.1",
        "source": {
            "platform": "facebook",
            "source_url": None,
            "collection_method": "synthetic_test",
            "collected_at": "2026-10-08T12:00:00Z",
        },
        "post": {
            "text": "Verify your example account now",
            "images": ["data/raw/images/SVT_000001_01.jpg"],
            "embedded_urls": ["https://example.invalid/login"],
        },
        "ocr": {"completed": False, "text": None, "average_confidence": None},
        "brand": {"claimed_brand": "ExampleBrand", "detected_brand": None, "confidence": None},
        "destination": {
            "original_url": "https://example.invalid/login",
            "final_url": None,
            "domain": None,
            "screenshots": [],
        },
        "labels": {"is_scam": 1, "scam_type": "brand_impersonation", "label_status": "provisional"},
        "processing": {"preprocessed": False, "ocr_completed": False, "webpage_captured": False},
        "created_at": "2026-10-08T12:00:00Z",
        "updated_at": "2026-10-08T12:00:00Z",
    }
    for dotted, value in overrides.items():
        target = record
        *parents, leaf = dotted.split("__")
        for key in parents:
            target = target[key]
        target[leaf] = value
    return record


# --------------------------------------------------------------- classes


def test_enum_supports_legitimate() -> None:
    assert ScamType("legitimate") is ScamType.LEGITIMATE
    assert IsScam(0) is IsScam.LEGITIMATE


def test_enum_supports_phishing() -> None:
    assert ScamType("phishing") is ScamType.PHISHING
    assert ScamType.PHISHING in SCAM_CATEGORIES


def test_enum_supports_brand_impersonation() -> None:
    assert ScamType("brand_impersonation") is ScamType.BRAND_IMPERSONATION


def test_all_required_vocabularies() -> None:
    assert {t.value for t in ScamType} == {
        "legitimate", "phishing", "brand_impersonation", "financial_scam",
        "data_theft", "malware", "browser_abuse", "other_scam", "unknown",
    }
    assert {s.value for s in LabelStatus} == {"verified", "provisional", "needs_review", "not_annotated"}
    assert {t.value for t in MisinfoType} == {
        "real", "satire_parody", "misleading_content", "imposter_content",
        "false_connection", "manipulated_content", "unknown",
    }
    assert {"facebook", "instagram", "x", "tiktok", "whatsapp", "website", "other", "unknown"} <= {
        p.value for p in Platform
    }
    assert {m.value for m in CollectionMethod} == {
        "manual", "public_dataset", "api", "research_archive", "synthetic_test",
    }
    classes = allowed_classes()
    assert classes["is_scam"] == {"0": "legitimate", "1": "scam"}
    assert "unknown" not in classes["scam_categories"]


def test_brand_is_not_a_class() -> None:
    with pytest.raises(ValueError):
        ScamType("paypal")


# --------------------------------------------------------------- label rules


def test_valid_legitimate_label_passes() -> None:
    label = LabelInfo(is_scam=0, scam_type="legitimate", label_status="verified")
    assert label.is_scam is IsScam.LEGITIMATE


@pytest.mark.parametrize("scam_type", sorted(t.value for t in SCAM_CATEGORIES))
def test_valid_scam_labels_pass(scam_type: str) -> None:
    assert LabelInfo(is_scam=1, scam_type=scam_type, label_status="verified").scam_type.value == scam_type


def test_legitimate_with_phishing_rejected() -> None:
    with pytest.raises(ValidationError) as excinfo:
        LabelInfo(is_scam=0, scam_type="phishing", label_status="verified")
    assert "is_scam=0 (legitimate) requires scam_type 'legitimate'" in str(excinfo.value)


def test_scam_with_legitimate_type_rejected() -> None:
    assert check_label_consistency(IsScam.SCAM, ScamType.LEGITIMATE, LabelStatus.VERIFIED)


def test_unknown_type_only_when_not_verified() -> None:
    assert not check_label_consistency(IsScam.SCAM, ScamType.UNKNOWN, LabelStatus.PROVISIONAL)
    assert check_label_consistency(IsScam.SCAM, ScamType.UNKNOWN, LabelStatus.VERIFIED)


def test_undecided_binary_label_requires_needs_review() -> None:
    assert not check_label_consistency(None, ScamType.UNKNOWN, LabelStatus.NEEDS_REVIEW)
    assert check_label_consistency(None, ScamType.UNKNOWN, LabelStatus.VERIFIED)
    assert check_label_consistency(None, ScamType.PHISHING, LabelStatus.NEEDS_REVIEW)


def test_invalid_label_values_rejected() -> None:
    with pytest.raises(ValidationError):
        LabelInfo(is_scam=2, scam_type="phishing", label_status="verified")
    with pytest.raises(ValidationError):
        LabelInfo(is_scam=1, scam_type="phishing", label_status="maybe")


# ----------------------------------------------------- misinformation labels


@pytest.mark.parametrize(
    ("is_fake", "misinfo_type", "status", "ok"),
    [
        (IsFake.REAL, MisinfoType.REAL, LabelStatus.VERIFIED, True),
        (IsFake.FAKE, MisinfoType.FALSE_CONNECTION, LabelStatus.VERIFIED, True),
        (IsFake.FAKE, MisinfoType.UNKNOWN, LabelStatus.PROVISIONAL, True),
        (None, MisinfoType.UNKNOWN, LabelStatus.NOT_ANNOTATED, True),
        (None, MisinfoType.UNKNOWN, LabelStatus.NEEDS_REVIEW, True),
        (IsFake.REAL, MisinfoType.SATIRE_PARODY, LabelStatus.VERIFIED, False),
        (IsFake.FAKE, MisinfoType.REAL, LabelStatus.VERIFIED, False),
        (IsFake.FAKE, MisinfoType.UNKNOWN, LabelStatus.VERIFIED, False),
        (IsFake.FAKE, MisinfoType.SATIRE_PARODY, LabelStatus.NOT_ANNOTATED, False),
        (None, MisinfoType.REAL, LabelStatus.NOT_ANNOTATED, False),
        (None, MisinfoType.UNKNOWN, LabelStatus.VERIFIED, False),
    ],
)
def test_misinformation_consistency(is_fake, misinfo_type, status, ok) -> None:
    assert (check_misinformation_consistency(is_fake, misinfo_type, status) == []) is ok


def test_scam_not_annotated_requires_empty_is_scam() -> None:
    assert check_label_consistency(None, ScamType.UNKNOWN, LabelStatus.NOT_ANNOTATED) == []
    assert check_label_consistency(IsScam.SCAM, ScamType.PHISHING, LabelStatus.NOT_ANNOTATED)


def test_misinformation_only_sample_is_valid() -> None:
    record = _record()
    record["labels"] = {
        "is_scam": None, "scam_type": "unknown", "label_status": "not_annotated",
        "misinformation": {"is_fake": 1, "misinfo_type": "manipulated_content",
                           "label_status": "verified", "source_label": "fakeddit_6way=4"},
    }
    sample = DatasetSample.model_validate(record)
    assert not sample.labels.scam_annotated and sample.labels.misinformation.annotated


def test_sample_without_any_label_is_rejected() -> None:
    record = _record()
    record["labels"] = {"is_scam": None, "scam_type": "unknown", "label_status": "not_annotated"}
    with pytest.raises(ValidationError, match="scam label and/or a misinformation label"):
        DatasetSample.model_validate(record)


# --------------------------------------------------------------- full record


def test_example_record_validates_and_round_trips() -> None:
    sample = DatasetSample.model_validate(_record())
    dumped = sample.model_dump(mode="json")
    assert dumped["labels"] == {
        "is_scam": 1, "scam_type": "brand_impersonation", "label_status": "provisional", "notes": None,
        "misinformation": {"is_fake": None, "misinfo_type": "unknown", "label_status": "not_annotated",
                           "source_label": None},
    }
    assert dumped["created_at"] == "2026-10-08T12:00:00Z"
    assert dumped["destination"]["screenshots"] == []
    assert DatasetSample.model_validate(dumped) == sample


def test_future_fields_do_not_break_schema() -> None:
    record = _record()
    record["clip"] = {"top_brand": "ExampleBrand"}
    record["ocr"]["engine"] = "tesseract"
    sample = DatasetSample.model_validate(record)
    assert sample.model_dump(mode="json")["clip"] == {"top_brand": "ExampleBrand"}


def test_optional_future_outputs_may_be_null() -> None:
    sample = DatasetSample.model_validate(_record())
    assert sample.ocr.text is None and sample.brand.detected_brand is None
    assert sample.destination.final_url is None and sample.destination.domain is None


@pytest.mark.parametrize(
    ("override", "fragment"),
    [
        ({"labels__is_scam": 0, "labels__scam_type": "phishing"}, "is_scam=0"),
        ({"source__platform": "myspace"}, "platform"),
        ({"sample_id": "SCAM_001"}, "SVT_000001"),
        ({"sample_id": "SVT_000000"}, "SVT_000001"),
        ({"post__text": "  ", "post__images": []}, "post text and/or at least one image"),
        ({"post__images": ["data/raw/images/SVT_000002_01.jpg"]}, "image path"),
        ({"post__images": ["../../etc/passwd"]}, "image path"),
        ({"post__images": ["data/raw/images/SVT_000001_02.jpg"]}, "sequential"),
        ({"post__embedded_urls": ["javascript:alert(1)"], "destination__original_url": None}, "http"),
        ({"post__embedded_urls": [123], "destination__original_url": None}, "string"),
        ({"destination__screenshots": ["shot.png"]}, "screenshot path"),
        ({"processing__ocr_completed": True}, "ocr_completed"),
    ],
)
def test_invalid_records_rejected(override: dict, fragment: str) -> None:
    with pytest.raises(ValidationError) as excinfo:
        DatasetSample.model_validate(_record(**override))
    assert fragment in str(excinfo.value)


def test_text_only_and_no_url_records_are_valid() -> None:
    text_only = DatasetSample.model_validate(_record(post__images=[]))
    assert text_only.post.images == []
    no_url = DatasetSample.model_validate(_record(post__embedded_urls=[], destination__original_url=None))
    assert no_url.post.embedded_urls == []


def test_future_screenshot_naming_accepted() -> None:
    record = _record(
        destination__screenshots=["data/webpage_screenshots/SVT_000001_web_01.png"],
        processing__webpage_captured=True,
    )
    assert DatasetSample.model_validate(record).processing.webpage_captured is True
