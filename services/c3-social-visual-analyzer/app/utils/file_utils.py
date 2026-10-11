"""Safe filesystem helpers for handling untrusted uploads.

Uploaded images may come from malicious social-media posts, so nothing here
trusts client-supplied names or paths. Files are only ever written to
service-controlled directories using generated names, are never executed, and
are created exclusively so existing samples cannot be overwritten.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from app.config import ALLOWED_EXTENSIONS
from app.exceptions import InvalidSampleIdError, StorageError

logger = logging.getLogger(__name__)

SAMPLE_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
UNTRUSTED_SUFFIX = ".upload"
_COPY_CHUNK_SIZE = 1024 * 1024
_MAX_ORIGINAL_FILENAME_LENGTH = 255


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def validate_sample_id(sample_id: str | None) -> str:
    """Return ``sample_id`` stripped if it is safe, otherwise raise.

    Only ``[A-Za-z][A-Za-z0-9_-]{0,63}`` is accepted, which rules out path
    separators, ``..`` and drive letters (e.g. ``../../etc/passwd``).
    """
    if sample_id is None:
        raise InvalidSampleIdError()
    candidate = sample_id.strip()
    if not SAMPLE_ID_PATTERN.fullmatch(candidate):
        raise InvalidSampleIdError()
    return candidate


def sanitize_original_filename(filename: str | None) -> str | None:
    """Reduce a client filename to a harmless basename for metadata only."""
    if not filename:
        return None
    basename = re.split(r"[\\/]", filename)[-1]
    cleaned = "".join(ch for ch in basename if ch.isprintable()).strip()
    return cleaned[:_MAX_ORIGINAL_FILENAME_LENGTH] or None


def safe_suffix(filename: str | None) -> str:
    """Return the lowercase extension if allowed, else a neutral suffix."""
    if not filename:
        return UNTRUSTED_SUFFIX
    suffix = Path(sanitize_original_filename(filename) or "").suffix.lower()
    return suffix if suffix in ALLOWED_EXTENSIONS else UNTRUSTED_SUFFIX


def generate_safe_filename(sample_id: str, suffix: str) -> str:
    """Build ``<sample_id>_<random hex><suffix>`` for a validated sample id."""
    validate_sample_id(sample_id)
    if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
        raise ValueError(f"Unsafe file suffix: {suffix!r}")
    return f"{sample_id}_{uuid.uuid4().hex[:12]}{suffix}"


def ensure_within_directory(path: Path, base_dir: Path) -> Path:
    """Resolve ``path`` and guarantee it lives inside ``base_dir``."""
    resolved = path.resolve()
    base = base_dir.resolve()
    if not resolved.is_relative_to(base):
        raise StorageError("Refusing to access a path outside the service data directory.")
    return resolved


def to_record_path(path: Path, data_dir: Path) -> str:
    """Return a portable path like ``data/raw/x.jpg`` for dataset records.

    Paths are made relative to the parent of the data directory so records never
    contain machine-specific absolute paths.
    """
    resolved = ensure_within_directory(path, data_dir)
    return resolved.relative_to(data_dir.resolve().parent).as_posix()


DATASET_PATH_PREFIX = "data/"


def to_dataset_path(path: Path, data_dir: Path) -> str:
    """Return ``data/<relative path>`` regardless of the physical data folder name."""
    resolved = ensure_within_directory(path, data_dir)
    return DATASET_PATH_PREFIX + resolved.relative_to(data_dir.resolve()).as_posix()


def from_dataset_path(record_path: str, data_dir: Path) -> Path:
    """Resolve a ``data/...`` record path inside ``data_dir`` (raises if it escapes)."""
    if not isinstance(record_path, str) or not record_path.startswith(DATASET_PATH_PREFIX):
        raise StorageError("Dataset paths must start with 'data/'.")
    return ensure_within_directory(data_dir / record_path[len(DATASET_PATH_PREFIX):], data_dir)


def compute_sha256(path: Path) -> str:
    """Return the SHA-256 hex digest of a file (metadata only, not similarity)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_COPY_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class SavedUpload:
    """Outcome of streaming an upload to disk."""

    path: Path | None
    size_bytes: int
    exceeded_limit: bool


def save_stream_exclusive(
    source: BinaryIO,
    destination_dir: Path,
    filename: str,
    max_bytes: int,
) -> SavedUpload:
    """Stream ``source`` into ``destination_dir/filename`` without overwriting.

    The copy stops as soon as ``max_bytes`` is exceeded; the partial file is then
    removed (it is not a usable image) and ``exceeded_limit`` is reported so the
    caller can log a rejection record.
    """
    target = ensure_within_directory(destination_dir / filename, destination_dir)
    written = 0
    try:
        with target.open("xb") as out:
            while True:
                chunk = source.read(_COPY_CHUNK_SIZE)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    break
                out.write(chunk)
    except FileExistsError as exc:
        logger.error("Generated upload filename already exists: %s", filename)
        raise StorageError("Could not allocate a unique storage filename.") from exc
    except OSError as exc:
        logger.error("Filesystem write failed for upload %s: %s", filename, exc)
        raise StorageError("Failed to store the uploaded file.") from exc

    if written > max_bytes:
        target.unlink(missing_ok=True)
        return SavedUpload(path=None, size_bytes=written, exceeded_limit=True)
    return SavedUpload(path=target, size_bytes=written, exceeded_limit=False)


def move_file_safely(source: Path, destination_dir: Path) -> Path:
    """Move ``source`` into ``destination_dir`` keeping its (generated) name."""
    target = ensure_within_directory(destination_dir / source.name, destination_dir)
    if target.exists():
        target = target.with_name(f"{target.stem}_{uuid.uuid4().hex[:6]}{target.suffix}")
    try:
        shutil.move(str(source), str(target))
    except OSError as exc:
        logger.error("Failed to move %s into %s: %s", source.name, destination_dir.name, exc)
        raise StorageError("Failed to move file within service storage.") from exc
    return target


def atomic_write_json(path: Path, payload: Any) -> None:
    """Write JSON via a temp file + ``os.replace`` so readers never see half a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except OSError as exc:
        tmp_path.unlink(missing_ok=True)
        logger.error("Atomic JSON write failed for %s: %s", path.name, exc)
        raise StorageError("Failed to write service storage.") from exc
