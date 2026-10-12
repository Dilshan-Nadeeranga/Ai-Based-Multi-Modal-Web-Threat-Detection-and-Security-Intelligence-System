"""Collect raw HTML samples into data/raw/<label>/ and register them in metadata.

Part 1: Multilingual dataset preparation.

Why: a sample is only usable for training when its file sits in the right
label folder AND it has a validated metadata row. ``register_file`` does both
steps together, so the files on disk and metadata.csv cannot drift apart.
"""

from __future__ import annotations

import shutil
from datetime import date
from pathlib import Path

from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.schemas.dataset import SampleMetadata
from c2_analyzer.utils.hashing import sha256_file


def register_file(
    store: MetadataStore,
    source_file: Path,
    label: str,
    language: str,
    source: str,
    source_url: str,
    collection_date: date | None = None,
    notes: str | None = None,
    fetch_mode: str = "manual",
    final_url: str | None = None,
    http_status: int | None = None,
    content_type: str | None = None,
) -> tuple[SampleMetadata, list[str]]:
    """Copy an HTML file into ``data/raw/<label>/<sample_id>.html`` and add its metadata.

    If the file is already inside ``data/raw/<label>/`` it is left where it is.
    Nothing is copied unless the record is valid and not a duplicate.
    The change is in memory: call ``store.save()`` afterwards.

    The fetch_* arguments are filled by the automatic fetcher (Batch B); a
    hand-saved page keeps the defaults (fetch_mode="manual").

    Returns the new record and any warnings from ``store.add``.
    """
    source_file = Path(source_file).resolve()
    if not source_file.is_file():
        raise FileNotFoundError(f"File not found: {source_file}")

    sample_id = store.next_sample_id(label)  # also checks the label is known
    raw_dir = store.raw_dir.resolve()
    label_dir = raw_dir / label

    already_in_place = source_file.parent == label_dir
    if not already_in_place and raw_dir in source_file.parents:
        raise ValueError(
            f"{source_file} is already in data/raw but not in the '{label}' folder; "
            "move it or register it with its correct label"
        )
    target = source_file if already_in_place else label_dir / f"{sample_id}.html"

    # 1. Build and validate the record first (raises on any bad value).
    record = SampleMetadata(
        sample_id=sample_id,
        file_path=f"{label}/{target.name}",
        label=label,
        language=language,
        source=source,
        source_url=source_url,
        collection_date=collection_date or date.today(),
        sha256=sha256_file(source_file),
        file_size_bytes=source_file.stat().st_size,
        fetch_mode=fetch_mode,
        final_url=final_url,
        http_status=http_status,
        content_type=content_type,
        notes=notes,
    )
    # 2. Reject duplicates before touching the disk.
    store.check_can_add(record)

    # 3. Copy the file (never overwrite something that is already there).
    if not already_in_place:
        if target.exists():
            raise FileExistsError(f"{target} already exists but is not registered; run 'validate'")
        label_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file, target)

    # 4. Add the metadata row.
    warnings = store.add(record)
    return record, warnings


def save_sample(html: str, label: str, source: str, source_url: str | None = None) -> Path:
    """Store one downloaded HTML sample under its label folder and return its path."""
    # TODO (Part 1, later batch): used by automated collectors (needs network).
    raise NotImplementedError
