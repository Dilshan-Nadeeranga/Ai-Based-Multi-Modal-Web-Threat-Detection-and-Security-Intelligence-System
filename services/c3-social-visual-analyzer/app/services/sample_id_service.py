"""Label-independent dataset sample IDs (``SVT_000001``) and file naming.

``SVT`` = Social Visual Threat. The class is deliberately not part of the ID so
labels can be corrected later without renaming files or breaking joins.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from app.exceptions import InvalidDatasetSampleIdError

SAMPLE_ID_PREFIX = "SVT"
SAMPLE_ID_DIGITS = 6
MAX_SAMPLE_NUMBER = 10**SAMPLE_ID_DIGITS - 1
SAMPLE_ID_PATTERN = re.compile(rf"^{SAMPLE_ID_PREFIX}_(\d{{{SAMPLE_ID_DIGITS}}})$")

_FILE_SAMPLE_PREFIX = re.compile(rf"^({SAMPLE_ID_PREFIX}_\d{{{SAMPLE_ID_DIGITS}}})(?:_|\.|$)")


def format_sample_id(number: int) -> str:
    """``1 -> 'SVT_000001'``."""
    if not 1 <= number <= MAX_SAMPLE_NUMBER:
        raise ValueError(f"Sample number must be between 1 and {MAX_SAMPLE_NUMBER}")
    return f"{SAMPLE_ID_PREFIX}_{number:0{SAMPLE_ID_DIGITS}d}"


def parse_sample_number(sample_id: str) -> int:
    """``'SVT_000042' -> 42``; raises for anything else."""
    match = SAMPLE_ID_PATTERN.fullmatch(sample_id.strip()) if isinstance(sample_id, str) else None
    if match is None or int(match.group(1)) == 0:
        raise InvalidDatasetSampleIdError()
    return int(match.group(1))


def validate_dataset_sample_id(sample_id: str) -> str:
    """Return the normalized ID if it matches ``SVT_000001``..``SVT_999999``."""
    parse_sample_number(sample_id)
    return sample_id.strip()


def image_filename(sample_id: str, index: int, extension: str) -> str:
    """``('SVT_000010', 1, '.jpg') -> 'SVT_000010_01.jpg'`` (numbering starts at 01)."""
    if not 1 <= index <= 99:
        raise ValueError("Image index must be between 1 and 99")
    return f"{sample_id}_{index:02d}{extension}"


def screenshot_filename(sample_id: str, index: int) -> str:
    """Future webpage capture naming: ``SVT_000001_web_01.png``."""
    if not 1 <= index <= 99:
        raise ValueError("Screenshot index must be between 1 and 99")
    return f"{sample_id}_web_{index:02d}.png"


def sample_id_from_filename(name: str) -> str | None:
    """Extract ``SVT_000001`` from names like ``SVT_000001_02.jpg``."""
    match = _FILE_SAMPLE_PREFIX.match(name)
    return match.group(1) if match else None


def ids_used_by_files(directories: Iterable[Path]) -> set[str]:
    """Sample IDs that already own files on disk (even if metadata is missing)."""
    used: set[str] = set()
    for directory in directories:
        if not directory.is_dir():
            continue
        for entry in directory.iterdir():
            sample_id = sample_id_from_filename(entry.name)
            if sample_id:
                used.add(sample_id)
    return used


def next_sample_id(used_ids: Iterable[str]) -> str:
    """Return the ID after the highest used number (gaps are never reused)."""
    highest = 0
    for sample_id in used_ids:
        try:
            highest = max(highest, parse_sample_number(sample_id))
        except InvalidDatasetSampleIdError:
            continue
    if highest >= MAX_SAMPLE_NUMBER:
        raise ValueError("Sample ID space exhausted")
    return format_sample_id(highest + 1)
