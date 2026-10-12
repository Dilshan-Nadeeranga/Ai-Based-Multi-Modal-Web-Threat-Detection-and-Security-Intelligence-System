"""Pydantic schema for one dataset sample (= one social-media post).

Every section allows extra keys so later phases (OCR joins, CLIP, YOLO,
webpage capture, ...) can add fields without breaking older readers. Field
meanings are documented in ``docs/dataset_schema.md``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.config import ALLOWED_EXTENSIONS
from app.schemas.dataset_classes import (
    CollectionMethod,
    IsFake,
    IsScam,
    LabelStatus,
    MisinfoType,
    Platform,
    ScamType,
    check_label_consistency,
    check_misinformation_consistency,
)
from app.services.sample_id_service import SAMPLE_ID_PATTERN
from app.utils.url_utils import extract_urls, normalize_evidence_url

RAW_IMAGES_PREFIX = "data/raw/images/"
RAW_POSTS_PREFIX = "data/raw/posts/"
SCREENSHOTS_PREFIX = "data/webpage_screenshots/"

_IMAGE_EXTENSIONS = "|".join(sorted(ext.lstrip(".") for ext in ALLOWED_EXTENSIONS))


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def utc_now() -> datetime:
    """Current UTC time truncated to seconds (stable ISO-8601 output)."""
    return datetime.now(timezone.utc).replace(microsecond=0)


class _Section(BaseModel):
    model_config = ConfigDict(extra="allow", use_enum_values=False)


class SourceInfo(_Section):
    platform: Platform
    source_url: str | None = None
    collection_method: CollectionMethod
    collected_at: datetime
    source_dataset: str | None = Field(default=None, max_length=200)
    source_reference: str | None = Field(default=None, max_length=500)

    @field_validator("source_url")
    @classmethod
    def _check_source_url(cls, value: str | None) -> str | None:
        return normalize_evidence_url(value) if value else None

    @field_validator("collected_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return _as_utc(value)


class PostContent(_Section):
    text: str | None = None
    images: list[str] = Field(default_factory=list)
    embedded_urls: list[str] = Field(default_factory=list)
    raw_snapshot: str | None = None

    @field_validator("text")
    @classmethod
    def _normalize_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.replace("\r\n", "\n").replace("\r", "\n").strip()
        return text or None

    @field_validator("embedded_urls")
    @classmethod
    def _check_urls(cls, value: list[str]) -> list[str]:
        urls = [normalize_evidence_url(url) for url in value]
        if len(set(urls)) != len(urls):
            raise ValueError("embedded_urls contains duplicates")
        return urls


class OcrEvidence(_Section):
    completed: bool = False
    text: str | None = None
    average_confidence: float | None = Field(default=None, ge=0, le=100)


class BrandEvidence(_Section):
    claimed_brand: str | None = Field(default=None, max_length=100)
    detected_brand: str | None = Field(default=None, max_length=100)
    confidence: float | None = Field(default=None, ge=0, le=1)

    @field_validator("claimed_brand", "detected_brand")
    @classmethod
    def _blank_to_none(cls, value: str | None) -> str | None:
        return value.strip() or None if value else None


class DestinationEvidence(_Section):
    original_url: str | None = None
    final_url: str | None = None
    domain: str | None = None
    screenshots: list[str] = Field(default_factory=list)

    @field_validator("original_url", "final_url")
    @classmethod
    def _check_url(cls, value: str | None) -> str | None:
        return normalize_evidence_url(value) if value else None


class MisinformationLabel(_Section):
    """Fake-news label; defaults to "not annotated" for scam-only samples."""

    is_fake: IsFake | None = None
    misinfo_type: MisinfoType = MisinfoType.UNKNOWN
    label_status: LabelStatus = LabelStatus.NOT_ANNOTATED
    source_label: str | None = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def _consistent(self) -> "MisinformationLabel":
        problems = check_misinformation_consistency(self.is_fake, self.misinfo_type, self.label_status)
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @property
    def annotated(self) -> bool:
        return self.label_status is not LabelStatus.NOT_ANNOTATED


def _check_labels(is_scam: IsScam | None, scam_type: ScamType, label_status: LabelStatus,
                  misinformation: MisinformationLabel) -> None:
    problems = check_label_consistency(is_scam, scam_type, label_status)
    if not problems and label_status is LabelStatus.NOT_ANNOTATED and not misinformation.annotated:
        problems.append("a sample needs a scam label and/or a misinformation label")
    if problems:
        raise ValueError("; ".join(problems))


class LabelInfo(_Section):
    is_scam: IsScam | None
    scam_type: ScamType
    label_status: LabelStatus
    notes: str | None = Field(default=None, max_length=2000)
    misinformation: MisinformationLabel = Field(default_factory=MisinformationLabel)

    @model_validator(mode="after")
    def _consistent(self) -> "LabelInfo":
        _check_labels(self.is_scam, self.scam_type, self.label_status, self.misinformation)
        return self

    @property
    def scam_annotated(self) -> bool:
        return self.label_status is not LabelStatus.NOT_ANNOTATED


class ProcessingStatus(_Section):
    preprocessed: bool = False
    ocr_completed: bool = False
    webpage_captured: bool = False


class DatasetSample(_Section):
    """One social-media post with all of its evidence linked by ``sample_id``."""

    sample_id: str
    dataset_version: str
    source: SourceInfo
    post: PostContent
    ocr: OcrEvidence = Field(default_factory=OcrEvidence)
    brand: BrandEvidence = Field(default_factory=BrandEvidence)
    destination: DestinationEvidence = Field(default_factory=DestinationEvidence)
    labels: LabelInfo
    processing: ProcessingStatus = Field(default_factory=ProcessingStatus)
    created_at: datetime
    updated_at: datetime

    @field_validator("sample_id")
    @classmethod
    def _check_sample_id(cls, value: str) -> str:
        if not SAMPLE_ID_PATTERN.fullmatch(value) or value.endswith("_000000"):
            raise ValueError("sample_id must look like SVT_000001")
        return value

    @field_validator("created_at", "updated_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return _as_utc(value)

    @model_validator(mode="after")
    def _check_links(self) -> "DatasetSample":
        problems: list[str] = []
        sid = re.escape(self.sample_id)

        if not self.post.text and not self.post.images:
            problems.append("a sample needs post text and/or at least one image")

        image_pattern = re.compile(rf"^{re.escape(RAW_IMAGES_PREFIX)}{sid}_(\d{{2}})\.({_IMAGE_EXTENSIONS})$")
        numbers: list[int] = []
        for path in self.post.images:
            match = image_pattern.fullmatch(path)
            if not match:
                problems.append(
                    f"image path {path!r} must be {RAW_IMAGES_PREFIX}{self.sample_id}_NN.<jpg|jpeg|png|webp>"
                )
            else:
                numbers.append(int(match.group(1)))
        if len(set(self.post.images)) != len(self.post.images):
            problems.append("post.images contains duplicate paths")
        elif numbers and len(numbers) == len(self.post.images) and numbers != list(range(1, len(numbers) + 1)):
            problems.append("image numbering must be sequential starting at 01")

        if self.post.raw_snapshot is not None and self.post.raw_snapshot != f"{RAW_POSTS_PREFIX}{self.sample_id}.json":
            problems.append(f"post.raw_snapshot must be {RAW_POSTS_PREFIX}{self.sample_id}.json")

        shot_pattern = re.compile(rf"^{re.escape(SCREENSHOTS_PREFIX)}{sid}_web_\d{{2}}\.png$")
        for path in self.destination.screenshots:
            if not shot_pattern.fullmatch(path):
                problems.append(f"screenshot path {path!r} must be {SCREENSHOTS_PREFIX}{self.sample_id}_web_NN.png")

        if self.destination.original_url and self.destination.original_url not in (
            *self.post.embedded_urls, *extract_urls(self.post.text)
        ):
            problems.append("destination.original_url must be one of post.embedded_urls or a link in post.text")
        if self.processing.ocr_completed != self.ocr.completed:
            problems.append("processing.ocr_completed must match ocr.completed")
        if self.processing.webpage_captured and not self.destination.screenshots:
            problems.append("processing.webpage_captured is true but destination.screenshots is empty")
        if self.updated_at < self.created_at:
            problems.append("updated_at is earlier than created_at")

        if problems:
            raise ValueError("; ".join(problems))
        return self

    @property
    def is_synthetic(self) -> bool:
        return self.source.collection_method is CollectionMethod.SYNTHETIC_TEST


class LabelEvent(BaseModel):
    """One line of ``labels.jsonl``: an append-only history of annotations."""

    model_config = ConfigDict(extra="allow")

    sample_id: str
    is_scam: IsScam | None
    scam_type: ScamType
    label_status: LabelStatus
    notes: str | None = None
    misinformation: MisinformationLabel = Field(default_factory=MisinformationLabel)
    event: str = "initial_label"
    labelled_at: datetime

    @model_validator(mode="after")
    def _consistent(self) -> "LabelEvent":
        _check_labels(self.is_scam, self.scam_type, self.label_status, self.misinformation)
        return self
