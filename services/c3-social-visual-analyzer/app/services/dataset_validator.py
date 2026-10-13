"""Whole-dataset integrity checks for ``dataset_metadata.jsonl`` and ``webpage_captures.jsonl``."""

from __future__ import annotations

import hashlib
import io
import logging
from collections import Counter
from pathlib import Path
from typing import Literal

from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, ValidationError

from app.config import Settings
from app.exceptions import StorageError
from app.schemas.capture_schema import WebpageCapture
from app.schemas.dataset_schema import DatasetSample, LabelEvent
from app.services.capture_service import candidate_urls
from app.services.image_validator import ImageValidator
from app.services.metadata_service import MetadataStore, read_jsonl
from app.utils.file_utils import from_dataset_path

logger = logging.getLogger(__name__)

Severity = Literal["error", "warning"]


class Finding(BaseModel):
    severity: Severity
    code: str
    message: str
    line: int | None = None
    sample_id: str | None = None


class DatasetValidationReport(BaseModel):
    valid: bool
    metadata_file: str
    records_checked: int
    valid_records: int
    error_count: int
    warning_count: int
    findings: list[Finding]


def _schema_finding_code(location: tuple[object, ...], error_type: str, message: str) -> str:
    path = ".".join(str(part) for part in location)
    if error_type == "missing":
        return "REQUIRED_FIELD_MISSING"
    if path.startswith("labels"):
        return "INVALID_LABEL" if path != "labels" else "LABEL_INCONSISTENT"
    if path == "source.platform":
        return "INVALID_PLATFORM"
    if path == "sample_id":
        return "INVALID_SAMPLE_ID"
    if "url" in path:
        return "INVALID_URL"
    if "image path" in message or "images" in path:
        return "INVALID_IMAGE_PATH"
    return "SCHEMA_ERROR"


class DatasetValidator:
    """Validates every record plus cross-record and file-system invariants."""

    def __init__(self, settings: Settings, check_image_content: bool = True) -> None:
        self.settings = settings
        self.store = MetadataStore(settings.dataset_metadata_path, settings.labels_path)
        self.check_image_content = check_image_content
        self._image_validator = ImageValidator(settings)

    def validate(self) -> DatasetValidationReport:
        findings: list[Finding] = []
        metadata = self.store.read_metadata()

        if not metadata.exists:
            findings.append(
                Finding(severity="warning", code="METADATA_MISSING", message="dataset_metadata.jsonl does not exist yet (empty dataset)")
            )
        for issue in metadata.issues:
            findings.append(Finding(severity="error", code="INVALID_JSONL", message=issue.message, line=issue.line))

        samples: list[tuple[int, DatasetSample]] = []
        for line, row in metadata.rows:
            sample_id = row.get("sample_id") if isinstance(row.get("sample_id"), str) else None
            try:
                samples.append((line, DatasetSample.model_validate(row)))
            except ValidationError as exc:
                for error in exc.errors():
                    message = str(error.get("msg", "")).removeprefix("Value error, ")
                    location = tuple(error.get("loc", ()))
                    findings.append(
                        Finding(
                            severity="error",
                            code=_schema_finding_code(location, str(error.get("type")), message),
                            message=f"{'.'.join(map(str, location)) or 'record'}: {message}",
                            line=line,
                            sample_id=sample_id,
                        )
                    )

        findings.extend(self._check_duplicates(metadata.rows))
        referenced_images: set[Path] = set()
        for line, sample in samples:
            findings.extend(self._check_files(line, sample, referenced_images))
        findings.extend(self._check_labels({s.sample_id: s for _, s in samples}))
        findings.extend(self._check_orphan_images(referenced_images))
        findings.extend(self._check_captures({s.sample_id: s for _, s in samples}))

        errors = sum(1 for f in findings if f.severity == "error")
        warnings = len(findings) - errors
        report = DatasetValidationReport(
            valid=errors == 0,
            metadata_file="data/annotations/dataset_metadata.jsonl",
            records_checked=len(metadata.rows) + len(metadata.issues),
            valid_records=len(samples),
            error_count=errors,
            warning_count=warnings,
            findings=findings,
        )
        if report.valid:
            logger.info("Dataset validation passed: %d records, %d warnings", report.records_checked, warnings)
        else:
            logger.error("Dataset validation failed: %d errors, %d warnings", errors, warnings)
        return report

    # ------------------------------------------------------------------ checks

    @staticmethod
    def _check_duplicates(rows: list[tuple[int, dict]]) -> list[Finding]:
        findings: list[Finding] = []
        id_counts = Counter(row.get("sample_id") for _, row in rows if isinstance(row.get("sample_id"), str))
        for sample_id, count in id_counts.items():
            if count > 1:
                lines = [line for line, row in rows if row.get("sample_id") == sample_id]
                findings.append(
                    Finding(
                        severity="error",
                        code="DUPLICATE_SAMPLE_ID",
                        message=f"sample_id appears {count} times (lines {', '.join(map(str, lines))})",
                        sample_id=sample_id,
                    )
                )

        owners: dict[str, str] = {}
        for line, row in rows:
            post = row.get("post") if isinstance(row.get("post"), dict) else {}
            images = post.get("images") if isinstance(post.get("images"), list) else []
            for image in images:
                if not isinstance(image, str):
                    continue
                if image in owners and owners[image] != f"{row.get('sample_id')}@{line}":
                    findings.append(
                        Finding(
                            severity="error",
                            code="DUPLICATE_IMAGE_PATH",
                            message=f"image {image} is referenced by more than one record",
                            line=line,
                            sample_id=row.get("sample_id"),
                        )
                    )
                owners.setdefault(image, f"{row.get('sample_id')}@{line}")
        return findings

    def _resolve(self, record_path: str, line: int, sample_id: str, findings: list[Finding]) -> Path | None:
        try:
            return from_dataset_path(record_path, self.settings.data_dir)
        except StorageError:
            findings.append(
                Finding(
                    severity="error",
                    code="UNSAFE_PATH",
                    message=f"{record_path} points outside the component data/ directory",
                    line=line,
                    sample_id=sample_id,
                )
            )
            return None

    def _check_files(self, line: int, sample: DatasetSample, referenced: set[Path]) -> list[Finding]:
        findings: list[Finding] = []
        sid = sample.sample_id
        for image in sample.post.images:
            path = self._resolve(image, line, sid, findings)
            if path is None:
                continue
            referenced.add(path)
            if not path.is_file():
                logger.error("Image path missing: %s (%s)", image, sid)
                findings.append(Finding(severity="error", code="IMAGE_MISSING", message=f"{image} does not exist", line=line, sample_id=sid))
            elif self.check_image_content:
                result = self._image_validator.validate(path)
                if not result.valid:
                    findings.append(
                        Finding(severity="error", code="IMAGE_INVALID", message=f"{image}: {result.error}", line=line, sample_id=sid)
                    )

        for shot in sample.destination.screenshots:
            path = self._resolve(shot, line, sid, findings)
            if path is not None and not path.is_file():
                findings.append(Finding(severity="error", code="SCREENSHOT_MISSING", message=f"{shot} does not exist", line=line, sample_id=sid))

        if sample.post.raw_snapshot:
            path = self._resolve(sample.post.raw_snapshot, line, sid, findings)
            if path is not None and not path.is_file():
                findings.append(
                    Finding(severity="warning", code="SNAPSHOT_MISSING", message=f"{sample.post.raw_snapshot} does not exist", line=line, sample_id=sid)
                )

        if sample.dataset_version != self.settings.dataset_version:
            findings.append(
                Finding(
                    severity="warning",
                    code="VERSION_MISMATCH",
                    message=f"record uses dataset_version {sample.dataset_version}, current is {self.settings.dataset_version}",
                    line=line,
                    sample_id=sid,
                )
            )
        if sample.is_synthetic:
            findings.append(
                Finding(
                    severity="warning",
                    code="SYNTHETIC_SAMPLE",
                    message="synthetic_test sample present; it is excluded from research statistics",
                    line=line,
                    sample_id=sid,
                )
            )
        return findings

    def _check_labels(self, samples: dict[str, DatasetSample]) -> list[Finding]:
        findings: list[Finding] = []
        labels = self.store.read_labels()
        for issue in labels.issues:
            findings.append(
                Finding(severity="error", code="INVALID_LABEL_JSONL", message=f"labels.jsonl: {issue.message}", line=issue.line)
            )
        latest: dict[str, LabelEvent] = {}
        for line, row in labels.rows:
            try:
                event = LabelEvent.model_validate(row)
            except ValidationError as exc:
                findings.append(
                    Finding(
                        severity="error",
                        code="INVALID_LABEL",
                        message=f"labels.jsonl line {line}: {exc.errors()[0].get('msg')}",
                        line=line,
                        sample_id=row.get("sample_id") if isinstance(row.get("sample_id"), str) else None,
                    )
                )
                continue
            if event.sample_id not in samples:
                findings.append(
                    Finding(severity="error", code="LABEL_ORPHAN", message=f"labels.jsonl line {line} refers to an unknown sample", sample_id=event.sample_id)
                )
            latest[event.sample_id] = event

        for sample_id, sample in samples.items():
            event = latest.get(sample_id)
            if event is None:
                findings.append(
                    Finding(severity="warning", code="LABEL_EVENT_MISSING", message="no entry in labels.jsonl", sample_id=sample_id)
                )
            elif (event.is_scam, event.scam_type, event.label_status, event.misinformation) != (
                sample.labels.is_scam,
                sample.labels.scam_type,
                sample.labels.label_status,
                sample.labels.misinformation,
            ):
                findings.append(
                    Finding(
                        severity="warning",
                        code="LABEL_MISMATCH",
                        message="latest labels.jsonl entry differs from the metadata labels",
                        sample_id=sample_id,
                    )
                )
        return findings

    def _check_orphan_images(self, referenced: set[Path]) -> list[Finding]:
        directory = self.settings.raw_images_dir
        if not directory.is_dir():
            return []
        findings: list[Finding] = []
        for entry in sorted(directory.iterdir()):
            if entry.name == ".gitkeep" or not entry.is_file():
                continue
            if entry.resolve() not in referenced:
                findings.append(
                    Finding(
                        severity="warning",
                        code="ORPHAN_IMAGE_FILE",
                        message=f"data/raw/images/{entry.name} is not referenced by any record",
                    )
                )
        return findings

    def _check_captures(self, samples: dict[str, DatasetSample]) -> list[Finding]:
        """``webpage_captures.jsonl``: schema, sample/URL links and screenshot files."""
        findings: list[Finding] = []
        captures = read_jsonl(self.settings.webpage_captures_path)
        for issue in captures.issues:
            findings.append(Finding(severity="error", code="INVALID_CAPTURE_JSONL",
                                    message=f"webpage_captures.jsonl: {issue.message}", line=issue.line))
        owners: dict[str, int] = {}
        referenced: set[Path] = set()
        for line, row in captures.rows:
            raw_id = row.get("sample_id") if isinstance(row.get("sample_id"), str) else None
            try:
                capture = WebpageCapture.model_validate(row)
            except ValidationError as exc:
                error = exc.errors()[0]
                where = ".".join(map(str, error.get("loc", ()))) or "record"
                findings.append(Finding(
                    severity="error", code="INVALID_CAPTURE",
                    message=f"webpage_captures.jsonl line {line}: {where}: "
                            f"{str(error.get('msg', '')).removeprefix('Value error, ')}",
                    line=line, sample_id=raw_id,
                ))
                continue
            sid = capture.sample_id
            sample = samples.get(sid)
            if sample is None:
                findings.append(Finding(severity="error", code="CAPTURE_ORPHAN",
                                        message=f"webpage_captures.jsonl line {line} refers to an unknown sample",
                                        line=line, sample_id=sid))
            elif capture.original_url not in candidate_urls(sample):
                findings.append(Finding(severity="error", code="CAPTURE_URL_MISMATCH",
                                        message=f"webpage_captures.jsonl line {line}: {capture.original_url} "
                                                "is not a URL of the post", line=line, sample_id=sid))
            if not capture.screenshot:
                continue
            if capture.screenshot in owners:
                findings.append(Finding(severity="error", code="DUPLICATE_SCREENSHOT_PATH",
                                        message=f"{capture.screenshot} is used by lines {owners[capture.screenshot]} "
                                                f"and {line}", line=line, sample_id=sid))
            owners.setdefault(capture.screenshot, line)
            path = self._resolve(capture.screenshot, line, sid, findings)
            if path is None:
                continue
            referenced.add(path)
            findings.extend(self._check_screenshot_file(path, capture, line))

        directory = self.settings.webpage_screenshots_dir
        if directory.is_dir():
            for entry in sorted(directory.iterdir()):
                if entry.is_file() and entry.name != ".gitkeep" and entry.resolve() not in referenced:
                    findings.append(Finding(
                        severity="warning", code="ORPHAN_SCREENSHOT_FILE",
                        message=f"data/webpage_screenshots/{entry.name} is not referenced by any capture record",
                    ))
        return findings

    @staticmethod
    def _check_screenshot_file(path: Path, capture: WebpageCapture, line: int) -> list[Finding]:
        sid = capture.sample_id
        if not path.is_file():
            return [Finding(severity="error", code="SCREENSHOT_MISSING",
                            message=f"{capture.screenshot} does not exist", line=line, sample_id=sid)]
        data = path.read_bytes()
        try:
            with Image.open(io.BytesIO(data)) as image:
                image.verify()
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            return [Finding(severity="error", code="SCREENSHOT_INVALID",
                            message=f"{capture.screenshot} is not a readable image ({exc})", line=line, sample_id=sid)]
        if capture.screenshot_sha256 and hashlib.sha256(data).hexdigest() != capture.screenshot_sha256:
            return [Finding(severity="error", code="SCREENSHOT_MODIFIED",
                            message=f"{capture.screenshot} does not match the recorded sha256",
                            line=line, sample_id=sid)]
        return []
