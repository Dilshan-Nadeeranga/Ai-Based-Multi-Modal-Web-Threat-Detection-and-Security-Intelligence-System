"""Append-only storage for ``dataset_metadata.jsonl`` and ``labels.jsonl``.

Adding a sample appends exactly one line; the file is never rewritten.
Malformed lines are reported explicitly (with line numbers) and never dropped.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.exceptions import AnnotationStorageError, SampleNotFoundError
from app.schemas.dataset_schema import DatasetSample, LabelEvent
from app.services.annotation_service import JsonlWriter

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class JsonlIssue:
    line: int
    message: str


@dataclass
class JsonlReadResult:
    """Parsed JSON objects plus the line number each came from."""

    rows: list[tuple[int, dict[str, Any]]] = field(default_factory=list)
    issues: list[JsonlIssue] = field(default_factory=list)
    exists: bool = False


def read_jsonl(path: Path) -> JsonlReadResult:
    """Parse a JSONL file without discarding anything silently.

    Blank lines are ignored; undecodable, non-JSON or non-object lines are
    returned as issues.
    """
    result = JsonlReadResult(exists=path.exists())
    if not result.exists:
        return result
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        logger.error("Failed to read %s: %s", path.name, exc)
        raise AnnotationStorageError() from exc

    for number, raw_line in enumerate(raw_bytes.split(b"\n"), start=1):
        if not raw_line.strip():
            continue
        try:
            row = json.loads(raw_line.decode("utf-8"))
        except UnicodeDecodeError:
            result.issues.append(JsonlIssue(number, "line is not valid UTF-8"))
            continue
        except json.JSONDecodeError as exc:
            result.issues.append(JsonlIssue(number, f"invalid JSON: {exc.msg}"))
            continue
        if not isinstance(row, dict):
            result.issues.append(JsonlIssue(number, "line is not a JSON object"))
            continue
        result.rows.append((number, row))

    for issue in result.issues:
        logger.warning("Metadata line malformed: %s line %d: %s", path.name, issue.line, issue.message)
    return result


class MetadataStore:
    """Reads and appends dataset sample records and label events."""

    def __init__(self, metadata_path: Path, labels_path: Path) -> None:
        self.metadata_path = metadata_path
        self.labels_path = labels_path
        self._metadata_writer = JsonlWriter(metadata_path)
        self._labels_writer = JsonlWriter(labels_path)

    def read_metadata(self) -> JsonlReadResult:
        return read_jsonl(self.metadata_path)

    def read_labels(self) -> JsonlReadResult:
        return read_jsonl(self.labels_path)

    def existing_sample_ids(self) -> set[str]:
        """IDs present in metadata. Refuses to guess if any line is malformed."""
        result = self.read_metadata()
        if result.issues:
            first = result.issues[0]
            raise AnnotationStorageError(
                f"dataset_metadata.jsonl has {len(result.issues)} malformed line(s) "
                f"(first at line {first.line}: {first.message}). Fix it before adding samples."
            )
        return {str(row.get("sample_id")) for _, row in result.rows if row.get("sample_id")}

    def get_sample(self, sample_id: str) -> DatasetSample:
        """Return the record for ``sample_id`` (raises if missing or invalid)."""
        for line, row in self.read_metadata().rows:
            if row.get("sample_id") != sample_id:
                continue
            try:
                return DatasetSample.model_validate(row)
            except ValidationError as exc:
                logger.error("Stored record %s (line %d) is invalid: %s", sample_id, line, exc)
                raise AnnotationStorageError(
                    f"The stored record for {sample_id} (line {line}) does not match the schema."
                ) from exc
        raise SampleNotFoundError()

    def append_sample(self, sample: DatasetSample) -> None:
        self._metadata_writer.append(sample.model_dump(mode="json"))
        logger.info("Metadata appended: %s", sample.sample_id)

    def append_label(self, event: LabelEvent) -> None:
        self._labels_writer.append(event.model_dump(mode="json"))
        logger.info("Label event appended: %s (%s)", event.sample_id, event.event)
