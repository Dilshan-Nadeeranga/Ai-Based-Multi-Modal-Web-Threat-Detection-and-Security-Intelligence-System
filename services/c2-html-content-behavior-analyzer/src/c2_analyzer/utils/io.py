"""Read/write helpers for JSON, JSONL, CSV and HTML files.

Shared (used across Parts 1-9).

Why: several stores (metadata.csv, candidates.csv) must never be left
half-written if the program crashes or is stopped with Ctrl+C. The atomic
writer lives here once and every store uses it. On Windows another program
(Excel, an antivirus scan) can briefly lock the CSV, so the final rename is
retried a few times before giving a clear "close the file" error.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import pandas as pd

# Waits between the 10 rename attempts: they grow from 0.2 s, about 3 s in total.
# Antivirus locks usually clear within a second; Excel keeps the lock until closed.
REPLACE_RETRY_DELAYS = (0.2, 0.2, 0.25, 0.25, 0.3, 0.35, 0.4, 0.45, 0.6)


class FileSaveError(RuntimeError):
    """A file could not be saved because another program keeps it locked."""


def remove_quietly(path: Path) -> bool:
    """Delete ``path`` if possible. Returns False if it is still there (e.g. locked)."""
    try:
        Path(path).unlink(missing_ok=True)
        return True
    except OSError:
        return False


def replace_with_retry(source: Path, target: Path) -> None:
    """``os.replace(source, target)``, retried while Windows reports the target as locked."""
    for delay in REPLACE_RETRY_DELAYS:
        try:
            os.replace(source, target)
            return
        except PermissionError:  # WinError 5/32: file open in Excel or being scanned
            time.sleep(delay)
    os.replace(source, target)  # last attempt: any error now goes to the caller


def atomic_write_csv(df: pd.DataFrame, path: Path, columns: list[str]) -> None:
    """Write ``df`` to ``path`` atomically: temp file next to it, then rename over it.

    ``os.replace`` is atomic on the same disk, so after a crash the CSV is
    either the old version or the new one - never half-written. The temp file
    is removed whenever the save does not complete.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            # lineterminator="\n": same file on Windows and Linux (clean git diffs)
            df.to_csv(handle, index=False, columns=columns, lineterminator="\n")
        try:
            replace_with_retry(Path(temp_name), path)
        except PermissionError as error:
            raise FileSaveError(
                f"Could not save {path}. Close it in Excel or any other program "
                "and run the command again."
            ) from error
    except BaseException:
        remove_quietly(Path(temp_name))
        raise


def read_csv_as_strings(path: Path) -> pd.DataFrame:
    """Read a CSV keeping every cell exactly as written.

    dtype=str + keep_default_na=False: "000123" stays a string and empty cells
    stay "" instead of becoming NaN.
    """
    return pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8")


def atomic_write_text(text: str, path: Path) -> None:
    """Write UTF-8 text atomically (temp file + rename), like ``atomic_write_csv``.

    Used for the Part 2 outputs: a crash or Ctrl+C never leaves a half-written
    JSON file that a later run would mistake for a finished one.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        # newline="\n": the same bytes on Windows and Linux
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        try:
            replace_with_retry(Path(temp_name), path)
        except PermissionError as error:
            raise FileSaveError(
                f"Could not save {path}: it is locked by another program."
            ) from error
    except BaseException:
        remove_quietly(Path(temp_name))
        raise


def read_json(path: Path) -> Any:
    """Read a UTF-8 JSON file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(data: Any, path: Path) -> None:
    """Write ``data`` as pretty UTF-8 JSON (Sinhala/Tamil stay readable), atomically."""
    atomic_write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", path)


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV file into a list of row dicts."""
    raise NotImplementedError


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    """Write row dicts to CSV."""
    raise NotImplementedError


def read_html(path: Path) -> str:
    """Read an HTML file, tolerating unknown encodings."""
    raise NotImplementedError
