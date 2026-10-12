"""Read/write helpers for JSON, JSONL, CSV and HTML files.

Shared (used across Parts 1-9).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


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
