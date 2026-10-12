"""Read/write helpers for JSON, JSONL, CSV and HTML files.

Shared (used across Parts 1-9).

Why: several stores (metadata.csv, candidates.csv) must never be left
half-written if the program crashes or is stopped with Ctrl+C. The atomic
writer lives here once and every store uses it.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import pandas as pd


def atomic_write_csv(df: pd.DataFrame, path: Path, columns: list[str]) -> None:
    """Write ``df`` to ``path`` atomically: temp file next to it, then rename over it.

    ``os.replace`` is atomic on the same disk, so after a crash the CSV is
    either the old version or the new one - never half-written.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            # lineterminator="\n": same file on Windows and Linux (clean git diffs)
            df.to_csv(handle, index=False, columns=columns, lineterminator="\n")
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def read_csv_as_strings(path: Path) -> pd.DataFrame:
    """Read a CSV keeping every cell exactly as written.

    dtype=str + keep_default_na=False: "000123" stays a string and empty cells
    stay "" instead of becoming NaN.
    """
    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")


def read_json(path: Path) -> Any:
    """Read a JSON file."""
    raise NotImplementedError


def write_json(data: Any, path: Path) -> None:
    """Write ``data`` as pretty UTF-8 JSON, creating parent dirs."""
    raise NotImplementedError


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV file into a list of row dicts."""
    raise NotImplementedError


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    """Write row dicts to CSV."""
    raise NotImplementedError


def read_html(path: Path) -> str:
    """Read an HTML file, tolerating unknown encodings."""
    raise NotImplementedError
