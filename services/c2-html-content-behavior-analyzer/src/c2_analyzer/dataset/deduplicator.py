"""Exact and near-duplicate removal (raw -> interim).

Part 1: Multilingual dataset preparation.
"""

from __future__ import annotations

from pathlib import Path


def find_exact_duplicates(paths: list[Path]) -> list[list[Path]]:
    """Group files with identical sha256."""
    raise NotImplementedError


def find_near_duplicates(paths: list[Path], threshold: float = 0.9) -> list[list[Path]]:
    """Group files whose MinHash Jaccard similarity >= ``threshold``."""
    raise NotImplementedError


def deduplicate(raw_dir: Path, interim_dir: Path) -> dict[str, int]:
    """Copy unique samples to ``interim_dir``; return counts kept/removed."""
    raise NotImplementedError
