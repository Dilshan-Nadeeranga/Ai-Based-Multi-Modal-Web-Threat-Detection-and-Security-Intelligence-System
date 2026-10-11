"""Ingestion of manually collected social-media posts into the dataset.

One call to :meth:`DatasetService.add_sample` creates one sample: it allocates
an ``SVT_000001`` ID, stores the original image bytes unchanged as
``data/raw/images/SVT_000001_01.jpg``, ``_02``..., writes a raw post snapshot,
and appends one linked record (text + images + URLs + labels) to
``dataset_metadata.jsonl`` plus an initial event to ``labels.jsonl``.

Nothing is scraped or fetched: inputs come from the researcher.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.config import Settings
from app.exceptions import (
    DatasetValidationError,
    SampleAlreadyExistsError,
    SourceImageNotFoundError,
    StorageError,
    SyntheticSampleNotAllowedError,
    UnsupportedImageError,
)
from app.schemas.dataset_classes import (
    CollectionMethod,
    IsFake,
    IsScam,
    LabelStatus,
    MisinfoType,
    Platform,
    ScamType,
)
from app.schemas.dataset_schema import (
    RAW_POSTS_PREFIX,
    BrandEvidence,
    DatasetSample,
    DestinationEvidence,
    LabelEvent,
    LabelInfo,
    MisinformationLabel,
    PostContent,
    SourceInfo,
    utc_now,
)
from app.services.image_validator import ImageValidator
from app.services.metadata_service import MetadataStore
from app.services.sample_id_service import (
    ids_used_by_files,
    image_filename,
    next_sample_id,
    validate_dataset_sample_id,
)
from app.utils.file_lock import FileLock
from app.utils.file_utils import (
    compute_sha256,
    ensure_within_directory,
    safe_suffix,
    sanitize_original_filename,
    save_stream_exclusive,
    to_dataset_path,
)
from app.utils.url_utils import normalize_evidence_url

logger = logging.getLogger(__name__)

FORMAT_EXTENSIONS: dict[str, str] = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp"}


@dataclass(frozen=True)
class ImageUpload:
    """An image supplied as a stream (e.g. a multipart upload)."""

    stream: BinaryIO
    filename: str | None


ImageSource = Path | ImageUpload


class NewSampleRequest(BaseModel):
    """Researcher-supplied fields for one post (before files are stored)."""

    model_config = ConfigDict(extra="forbid")

    platform: Platform
    post_text: str | None = None
    embedded_urls: list[str] = Field(default_factory=list)
    is_scam: IsScam | None
    scam_type: ScamType
    label_status: LabelStatus
    claimed_brand: str | None = Field(default=None, max_length=100)
    source_url: str | None = None
    collection_method: CollectionMethod = CollectionMethod.MANUAL
    collected_at: datetime | None = None
    source_dataset: str | None = Field(default=None, max_length=200)
    source_reference: str | None = Field(default=None, max_length=500)
    label_notes: str | None = Field(default=None, max_length=2000)
    is_fake: IsFake | None = None
    misinfo_type: MisinfoType = MisinfoType.UNKNOWN
    misinfo_label_status: LabelStatus = LabelStatus.NOT_ANNOTATED
    misinfo_source_label: str | None = Field(default=None, max_length=100)
    sample_id: str | None = None

    def labels(self) -> LabelInfo:
        """Both label tasks as a validated :class:`LabelInfo` (raises ValidationError)."""
        return LabelInfo(
            is_scam=self.is_scam,
            scam_type=self.scam_type,
            label_status=self.label_status,
            notes=self.label_notes,
            misinformation=MisinformationLabel(
                is_fake=self.is_fake,
                misinfo_type=self.misinfo_type,
                label_status=self.misinfo_label_status,
                source_label=self.misinfo_source_label,
            ),
        )

    @field_validator("embedded_urls", mode="before")
    @classmethod
    def _split_urls(cls, value: object) -> object:
        """Accept a list, or a single string separated by newlines/spaces/commas."""
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            urls: list[object] = []
            for item in value:
                if isinstance(item, str):
                    urls.extend(part for part in item.replace(",", " ").split() if part)
                else:
                    urls.append(item)
            return urls
        return value

    @field_validator(
        "post_text", "claimed_brand", "source_url", "source_dataset", "source_reference", "label_notes",
        "misinfo_source_label", "sample_id",
    )
    @classmethod
    def _blank_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value if value.strip() else None


def format_validation_error(exc: ValidationError) -> str:
    messages = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ()) if part != "__root__")
        message = str(error.get("msg", "invalid value")).removeprefix("Value error, ")
        messages.append(f"{location}: {message}" if location else message)
    return "; ".join(messages)


class DatasetService:
    """Creates linked dataset samples from researcher-provided evidence."""

    def __init__(self, settings: Settings, store: MetadataStore | None = None) -> None:
        self.settings = settings
        self.store = store or MetadataStore(settings.dataset_metadata_path, settings.labels_path)
        self._validator = ImageValidator(settings)
        settings.ensure_directories()

    # ------------------------------------------------------------------ public

    def add_sample(self, request: NewSampleRequest, images: Sequence[ImageSource] = ()) -> DatasetSample:
        """Validate, store and append one sample; returns the created record.

        On any failure, files written by this call are removed and nothing is
        appended, so a failed import leaves no partial sample behind.
        """
        settings = self.settings
        self._check_request(request, images)
        urls = self._clean_urls(request.embedded_urls)

        with FileLock(settings.dataset_lock_path, timeout_seconds=settings.dataset_lock_timeout_seconds):
            sample_id = self._allocate_sample_id(request.sample_id)
            created_files: list[Path] = []
            try:
                stored = [
                    self._store_image(source, sample_id, index, created_files)
                    for index, source in enumerate(images, start=1)
                ]
                now = utc_now()
                sample = self._build_sample(request, sample_id, urls, stored, now)
                snapshot = self._write_snapshot(sample, request, stored, created_files)
                sample = sample.model_copy(update={"post": sample.post.model_copy(update={"raw_snapshot": snapshot})})
                self.store.append_sample(sample)
            except BaseException:
                for path in created_files:
                    path.unlink(missing_ok=True)
                raise

            # The sample is committed once metadata is appended; a failure here
            # is reported by validate_dataset.py as a missing label event.
            self.store.append_label(
                LabelEvent(
                    sample_id=sample_id,
                    is_scam=sample.labels.is_scam,
                    scam_type=sample.labels.scam_type,
                    label_status=sample.labels.label_status,
                    notes=sample.labels.notes,
                    misinformation=sample.labels.misinformation,
                    labelled_at=sample.created_at,
                )
            )

        labels = sample.labels
        if LabelStatus.NEEDS_REVIEW in (labels.label_status, labels.misinformation.label_status):
            logger.warning("Sample %s needs review", sample_id)
        logger.info(
            "Sample created: %s platform=%s images=%d urls=%d is_scam=%s scam_type=%s status=%s "
            "is_fake=%s misinfo_type=%s misinfo_status=%s",
            sample_id,
            sample.source.platform.value,
            len(sample.post.images),
            len(sample.post.embedded_urls),
            None if labels.is_scam is None else int(labels.is_scam),
            labels.scam_type.value,
            labels.label_status.value,
            None if labels.misinformation.is_fake is None else int(labels.misinformation.is_fake),
            labels.misinformation.misinfo_type.value,
            labels.misinformation.label_status.value,
        )
        return sample

    def get_sample(self, sample_id: str) -> DatasetSample:
        return self.store.get_sample(validate_dataset_sample_id(sample_id))

    # ------------------------------------------------------------------ steps

    def _check_request(self, request: NewSampleRequest, images: Sequence[ImageSource]) -> None:
        if request.collection_method is CollectionMethod.SYNTHETIC_TEST and not self.settings.dataset_allow_synthetic:
            logger.error("Refused synthetic_test sample for the research dataset")
            raise SyntheticSampleNotAllowedError()
        try:
            request.labels()
        except ValidationError as exc:
            message = format_validation_error(exc)
            logger.error("Invalid label: %s", message)
            raise DatasetValidationError(f"Invalid label: {message}") from exc
        if not (request.post_text and request.post_text.strip()) and not images:
            raise DatasetValidationError("A sample needs post text and/or at least one image.")
        if request.post_text and len(request.post_text) > self.settings.dataset_max_text_length:
            raise DatasetValidationError(
                f"post_text exceeds {self.settings.dataset_max_text_length} characters."
            )
        if len(images) > self.settings.dataset_max_images_per_sample:
            raise DatasetValidationError(
                f"At most {self.settings.dataset_max_images_per_sample} images per sample are allowed."
            )
        if not images:
            logger.warning("Missing optional image: sample has text only")

    def _clean_urls(self, raw_urls: list[str]) -> list[str]:
        urls: list[str] = []
        problems: list[str] = []
        for raw in raw_urls:
            try:
                url = normalize_evidence_url(raw)
            except ValueError as exc:
                problems.append(str(exc))
                continue
            if url in urls:
                logger.warning("Duplicate embedded URL ignored: %s", url)
                continue
            urls.append(url)
        if problems:
            raise DatasetValidationError("Malformed embedded URL: " + "; ".join(problems))
        if len(urls) > self.settings.dataset_max_urls_per_sample:
            raise DatasetValidationError(
                f"At most {self.settings.dataset_max_urls_per_sample} embedded URLs per sample are allowed."
            )
        if not urls:
            logger.warning("Missing optional URL: sample has no embedded URLs")
        return urls

    def _allocate_sample_id(self, requested: str | None) -> str:
        settings = self.settings
        used = self.store.existing_sample_ids() | ids_used_by_files(
            (settings.raw_images_dir, settings.raw_posts_dir, settings.webpage_screenshots_dir)
        )
        if requested is None:
            return next_sample_id(used)
        sample_id = validate_dataset_sample_id(requested)
        if sample_id in used:
            logger.error("Duplicate sample ID refused: %s", sample_id)
            raise SampleAlreadyExistsError(f"Dataset sample {sample_id} already exists.")
        return sample_id

    def _store_image(
        self,
        source: ImageSource,
        sample_id: str,
        index: int,
        created_files: list[Path],
    ) -> tuple[str, str | None, str]:
        """Copy one image unchanged into raw/images; returns (record path, original name, sha256)."""
        settings = self.settings
        if isinstance(source, Path):
            if not source.is_file():
                logger.error("Image path missing: %s", source.name)
                raise SourceImageNotFoundError(f"Image {index} ('{source.name}') does not exist or is not a file.")
            with source.open("rb") as handle:
                return self._store_image(ImageUpload(handle, source.name), sample_id, index, created_files)

        original_name = sanitize_original_filename(source.filename)
        staging_name = f".staging_{uuid.uuid4().hex}{safe_suffix(original_name)}"
        saved = save_stream_exclusive(
            source.stream, settings.raw_images_dir, staging_name, settings.max_image_size_bytes
        )
        if saved.exceeded_limit or saved.path is None:
            raise UnsupportedImageError(
                f"Image {index} exceeds the {settings.max_image_size_mb:g} MB size limit."
            )
        staging_path = saved.path
        created_files.append(staging_path)

        validation = self._validator.validate(staging_path)
        if not validation.valid or validation.format not in FORMAT_EXTENSIONS:
            raise UnsupportedImageError(
                f"Image {index} ('{original_name or 'upload'}') rejected: {validation.error or 'unsupported format'}."
            )

        final_path = ensure_within_directory(
            settings.raw_images_dir / image_filename(sample_id, index, FORMAT_EXTENSIONS[validation.format]),
            settings.raw_images_dir,
        )
        if final_path.exists():
            raise SampleAlreadyExistsError(f"Image file {final_path.name} already exists.")
        try:
            os.rename(staging_path, final_path)
        except OSError as exc:
            logger.error("Metadata write failed: could not store image %s: %s", final_path.name, exc)
            raise StorageError("Failed to store a sample image.") from exc
        created_files.remove(staging_path)
        created_files.append(final_path)
        logger.info("Image copied: %s -> %s", original_name, final_path.name)
        return to_dataset_path(final_path, settings.data_dir), original_name, compute_sha256(final_path)

    def _build_sample(
        self,
        request: NewSampleRequest,
        sample_id: str,
        urls: list[str],
        stored: list[tuple[str, str | None, str]],
        now: datetime,
    ) -> DatasetSample:
        try:
            return DatasetSample(
                sample_id=sample_id,
                dataset_version=self.settings.dataset_version,
                source=SourceInfo(
                    platform=request.platform,
                    source_url=request.source_url,
                    collection_method=request.collection_method,
                    collected_at=request.collected_at or now,
                    source_dataset=request.source_dataset,
                    source_reference=request.source_reference,
                ),
                post=PostContent(
                    text=request.post_text,
                    images=[path for path, _, _ in stored],
                    embedded_urls=urls,
                ),
                brand=BrandEvidence(claimed_brand=request.claimed_brand),
                destination=DestinationEvidence(original_url=urls[0] if urls else None),
                labels=request.labels(),
                created_at=now,
                updated_at=now,
            )
        except ValidationError as exc:
            raise DatasetValidationError(format_validation_error(exc)) from exc

    def _write_snapshot(
        self,
        sample: DatasetSample,
        request: NewSampleRequest,
        stored: list[tuple[str, str | None, str]],
        created_files: list[Path],
    ) -> str:
        """Write ``data/raw/posts/<id>.json``: the submission exactly as received."""
        path = self.settings.raw_posts_dir / f"{sample.sample_id}.json"
        snapshot = {
            "sample_id": sample.sample_id,
            "captured_at": sample.created_at.isoformat().replace("+00:00", "Z"),
            "platform": request.platform.value,
            "source_url": sample.source.source_url,
            "collection_method": request.collection_method.value,
            "post_text": request.post_text,
            "embedded_urls": request.embedded_urls,
            "claimed_brand": request.claimed_brand,
            "images": [
                {"stored_path": path, "original_filename": name, "sha256": sha}
                for path, name, sha in stored
            ],
        }
        try:
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump(snapshot, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
        except FileExistsError as exc:
            raise SampleAlreadyExistsError(f"Raw post snapshot for {sample.sample_id} already exists.") from exc
        except OSError as exc:
            logger.error("Metadata write failed: raw post snapshot %s: %s", path.name, exc)
            raise StorageError("Failed to write the raw post snapshot.") from exc
        created_files.append(path)
        return f"{RAW_POSTS_PREFIX}{sample.sample_id}.json"


def build_request(**fields: object) -> NewSampleRequest:
    """Create a :class:`NewSampleRequest`, turning schema errors into a controlled error."""
    try:
        return NewSampleRequest.model_validate(fields)
    except ValidationError as exc:
        message = format_validation_error(exc)
        logger.error("Invalid dataset sample input: %s", message)
        raise DatasetValidationError(message) from exc
