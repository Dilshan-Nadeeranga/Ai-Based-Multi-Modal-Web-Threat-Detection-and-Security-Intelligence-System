"""End-to-end Phase 1 pipeline: safe save -> validate -> preprocess -> hash ->
duplicate check -> OCR -> persist.

Invalid images are moved to ``data/rejected/`` and logged in
``rejected_images.jsonl``; they are never hashed, OCR'd or deleted.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import BinaryIO

from PIL import Image

from app.config import PIPELINE_VERSION, Settings
from app.exceptions import SampleAlreadyExistsError, ServiceError
from app.schemas.image_schema import (
    DuplicateDetectionRecord,
    HashRecord,
    ImageValidationResult,
    ProcessedImageInfo,
    RejectionRecord,
)
from app.schemas.pipeline_schema import (
    DatasetRecord,
    PipelineResult,
    ProcessingMetadata,
    ValidationSummary,
)
from app.services.annotation_service import AnnotationService
from app.services.duplicate_detector import DuplicateDetector
from app.services.hash_store import HashStore
from app.services.image_hash_service import ImageHashService
from app.services.image_preprocessor import ImagePreprocessor, normalize_image, resize_image
from app.services.image_validator import ImageValidator
from app.services.ocr_service import OcrEngine, create_ocr_engine
from app.utils.file_utils import (
    compute_sha256,
    generate_safe_filename,
    move_file_safely,
    safe_suffix,
    sanitize_original_filename,
    save_stream_exclusive,
    to_record_path,
    utc_now_iso,
    validate_sample_id,
)

logger = logging.getLogger(__name__)


class ImagePipeline:
    """Orchestrates the Phase 1 services; each dependency is injectable."""

    def __init__(
        self,
        settings: Settings,
        validator: ImageValidator,
        preprocessor: ImagePreprocessor,
        hash_service: ImageHashService,
        hash_store: HashStore,
        duplicate_detector: DuplicateDetector,
        ocr_engine: OcrEngine,
        annotation_service: AnnotationService,
    ) -> None:
        self.settings = settings
        self.validator = validator
        self.preprocessor = preprocessor
        self.hash_service = hash_service
        self.hash_store = hash_store
        self.duplicate_detector = duplicate_detector
        self.ocr_engine = ocr_engine
        self.annotation_service = annotation_service
        self._commit_lock = threading.Lock()
        settings.ensure_directories()

    @classmethod
    def from_settings(cls, settings: Settings, ocr_engine: OcrEngine | None = None) -> "ImagePipeline":
        """Build a pipeline with the default service implementations."""
        hash_store = HashStore(settings.image_hashes_path)
        return cls(
            settings=settings,
            validator=ImageValidator(settings),
            preprocessor=ImagePreprocessor(
                max_width=settings.processed_max_width,
                max_height=settings.processed_max_height,
                background=settings.processed_background_color,
            ),
            hash_service=ImageHashService(settings.phash_hash_size),
            hash_store=hash_store,
            duplicate_detector=DuplicateDetector(hash_store, settings.phash_near_duplicate_threshold),
            ocr_engine=ocr_engine or create_ocr_engine(settings),
            annotation_service=AnnotationService(settings.ocr_results_path, settings.rejected_images_path),
        )

    # ------------------------------------------------------------------ entry points

    def process_upload(
        self,
        source: BinaryIO,
        original_filename: str | None,
        sample_id: str,
    ) -> PipelineResult:
        """Safely store an uploaded stream in ``data/raw/uploads/`` and process it."""
        sample_id = validate_sample_id(sample_id)
        self._ensure_sample_is_new(sample_id)
        clean_name = sanitize_original_filename(original_filename)
        logger.info("Image upload received: sample_id=%s filename=%r", sample_id, clean_name)

        filename = generate_safe_filename(sample_id, safe_suffix(clean_name))
        saved = save_stream_exclusive(
            source, self.settings.raw_uploads_dir, filename, self.settings.max_image_size_bytes
        )
        if saved.exceeded_limit or saved.path is None:
            validation = ImageValidationResult(
                valid=False,
                file_size_bytes=saved.size_bytes,
                error=f"File exceeds the {self.settings.max_image_size_mb:g} MB size limit",
                error_code="FILE_TOO_LARGE",
            )
            return self._reject(sample_id, None, validation, clean_name)
        return self._process_raw(saved.path, sample_id, clean_name)

    def process_post_image(
        self,
        image_path: Path,
        sample_id: str,
        original_filename: str | None = None,
    ) -> PipelineResult:
        """Process an image file for ``sample_id``.

        Files already inside ``data/raw/uploads/`` are processed in place; any
        other file is first copied there under a generated name.
        """
        sample_id = validate_sample_id(sample_id)
        path = Path(image_path)
        raw_dir = self.settings.raw_uploads_dir.resolve()

        if not path.is_file():
            self._ensure_sample_is_new(sample_id)
            return self._reject(sample_id, None, self.validator.validate(path), original_filename)

        resolved = path.resolve()
        if resolved.parent == raw_dir:
            self._ensure_sample_is_new(sample_id)
            return self._process_raw(resolved, sample_id, original_filename or path.name)

        with path.open("rb") as handle:
            return self.process_upload(handle, original_filename or path.name, sample_id)

    # ------------------------------------------------------------------ internals

    def _ensure_sample_is_new(self, sample_id: str) -> None:
        if self.hash_store.contains(sample_id):
            raise SampleAlreadyExistsError()

    def _reject(
        self,
        sample_id: str,
        raw_path: Path | None,
        validation: ImageValidationResult,
        original_filename: str | None,
    ) -> PipelineResult:
        """Quarantine an invalid file in ``data/rejected/`` and record why."""
        stored_path: str | None = None
        sha256: str | None = None
        if raw_path is not None and raw_path.is_file():
            sha256 = compute_sha256(raw_path)
            rejected_path = move_file_safely(raw_path, self.settings.rejected_dir)
            stored_path = to_record_path(rejected_path, self.settings.data_dir)

        rejection = RejectionRecord(
            sample_id=sample_id,
            reason=validation.error or "Invalid image",
            error_code=validation.error_code or "CORRUPTED_IMAGE",
            stored_path=stored_path,
            original_filename=original_filename,
            file_size_bytes=validation.file_size_bytes,
            sha256=sha256,
            created_at=utc_now_iso(),
        )
        self.annotation_service.save_rejection(rejection)
        logger.error(
            "Image rejected: sample_id=%s code=%s reason=%s",
            sample_id,
            rejection.error_code,
            rejection.reason,
        )
        return PipelineResult(
            sample_id=sample_id,
            status="rejected",
            validation=validation,
            rejection=rejection,
        )

    def _process_raw(
        self,
        raw_path: Path,
        sample_id: str,
        original_filename: str | None,
    ) -> PipelineResult:
        validation = self.validator.validate(raw_path)
        if not validation.valid:
            return self._reject(sample_id, raw_path, validation, original_filename)

        settings = self.settings
        original_sha256 = compute_sha256(raw_path)
        processed_path = settings.processed_images_dir / f"{raw_path.stem}.png"
        images_to_close: list[Image.Image] = []

        try:
            image, original_mode, transposed = self.preprocessor.load(raw_path)
            images_to_close.append(image)
            rgb = self.preprocessor.to_rgb(image)
            images_to_close.append(rgb)
            processed = self.preprocessor.resize(rgb)
            images_to_close.append(processed)
            self.preprocessor.save_png(processed, processed_path)

            normalized = normalize_image(processed)
            normalization_info = normalized.info()
            del normalized

            phash = self.hash_service.generate_phash(processed)
            hash_revision = self.hash_store.revision
            duplicate = self.duplicate_detector.find_duplicate(phash, exclude_sample_id=sample_id)

            ocr_input = rgb
            if max(rgb.size) > settings.ocr_max_side:
                ocr_input = resize_image(rgb, settings.ocr_max_side, settings.ocr_max_side)
                images_to_close.append(ocr_input)
            ocr_result = self.ocr_engine.extract(ocr_input)
            processed_size = processed.size
        except ServiceError:
            processed_path.unlink(missing_ok=True)
            raise
        finally:
            for item in images_to_close:
                item.close()

        image_info = ProcessedImageInfo(
            original_format=validation.format or "",
            original_mode=original_mode,
            original_width=validation.width or 0,
            original_height=validation.height or 0,
            original_file_size_bytes=validation.file_size_bytes or 0,
            original_sha256=original_sha256,
            exif_transposed=transposed,
            processed_width=processed_size[0],
            processed_height=processed_size[1],
            normalization=normalization_info,
        )

        with self._commit_lock:
            if self.hash_store.revision != hash_revision:
                duplicate = self.duplicate_detector.find_duplicate(phash, exclude_sample_id=sample_id)

            created_at = utc_now_iso()
            original_record_path = to_record_path(raw_path, settings.data_dir)
            processed_record_path = to_record_path(processed_path, settings.data_dir)
            record = DatasetRecord(
                sample_id=sample_id,
                original_filename=original_filename,
                original_image=original_record_path,
                processed_image=processed_record_path,
                image=image_info,
                validation=ValidationSummary(valid=True, error=None),
                duplicate_detection=DuplicateDetectionRecord(
                    phash=phash, **duplicate.model_dump()
                ),
                ocr=ocr_result,
                processing=ProcessingMetadata(
                    pipeline_version=PIPELINE_VERSION,
                    processed_max_width=settings.processed_max_width,
                    processed_max_height=settings.processed_max_height,
                    background_color=list(settings.processed_background_color),
                    phash_hash_size=settings.phash_hash_size,
                    phash_near_duplicate_threshold=settings.phash_near_duplicate_threshold,
                    ocr_min_word_confidence=settings.ocr_min_word_confidence,
                    ocr_max_side=settings.ocr_max_side,
                ),
                created_at=created_at,
            )

            try:
                self.hash_store.add(
                    sample_id,
                    HashRecord(
                        file=processed_record_path,
                        phash=phash,
                        hash_size=self.hash_service.hash_size,
                        sha256=original_sha256,
                        duplicate_of=duplicate.matched_sample_id,
                        created_at=created_at,
                    ),
                )
            except ServiceError:
                processed_path.unlink(missing_ok=True)
                raise
            try:
                self.annotation_service.save_ocr_result(record)
            except ServiceError:
                self.hash_store.remove(sample_id)
                processed_path.unlink(missing_ok=True)
                raise

        return PipelineResult(
            sample_id=sample_id,
            status="success",
            validation=validation,
            record=record,
        )
