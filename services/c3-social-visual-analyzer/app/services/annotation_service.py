"""Append-only JSONL persistence for OCR results and rejected images."""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from app.exceptions import AnnotationStorageError

logger = logging.getLogger(__name__)


class JsonlWriter:
    """Thread-safe appender writing exactly one JSON object per line."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                prefix = "\n" if self._missing_trailing_newline() else ""
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(f"{prefix}{line}\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as exc:
                logger.error("Filesystem write failed for %s: %s", self.path.name, exc)
                raise AnnotationStorageError("Failed to write the annotation dataset.") from exc

    def _missing_trailing_newline(self) -> bool:
        """Detect a previously interrupted write so lines never get merged."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return False
        with self.path.open("rb") as handle:
            handle.seek(-1, os.SEEK_END)
            return handle.read(1) != b"\n"

    def read(self) -> Iterator[dict[str, Any]]:
        """Yield records, raising on malformed lines (blank lines are skipped)."""
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        logger.error("Malformed JSONL in %s at line %d", self.path.name, line_number)
                        raise AnnotationStorageError() from exc
                    if not isinstance(record, dict):
                        raise AnnotationStorageError()
                    yield record
        except (OSError, UnicodeDecodeError) as exc:
            logger.error("Failed to read %s: %s", self.path.name, exc)
            raise AnnotationStorageError() from exc


class AnnotationService:
    """Stores successful OCR results and rejection records as JSONL."""

    def __init__(self, ocr_results_path: Path, rejected_images_path: Path) -> None:
        self._ocr_results = JsonlWriter(ocr_results_path)
        self._rejections = JsonlWriter(rejected_images_path)

    def save_ocr_result(self, record: BaseModel) -> None:
        self._ocr_results.append(record.model_dump(mode="json"))
        logger.info("Dataset record saved: %s", getattr(record, "sample_id", "?"))

    def save_rejection(self, record: BaseModel) -> None:
        self._rejections.append(record.model_dump(mode="json"))
        logger.info("Rejection record saved: %s", getattr(record, "sample_id", "?"))

    def iter_ocr_results(self) -> Iterator[dict[str, Any]]:
        return self._ocr_results.read()

    def iter_rejections(self) -> Iterator[dict[str, Any]]:
        return self._rejections.read()
