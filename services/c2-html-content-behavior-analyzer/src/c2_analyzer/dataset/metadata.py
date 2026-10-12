"""Build and validate dataset metadata (metadata.csv).

Part 1: Multilingual dataset preparation.
"""

from __future__ import annotations

from pathlib import Path

from c2_analyzer.schemas.dataset import SampleMetadata


def build_metadata(raw_dir: Path) -> list[SampleMetadata]:
    """Scan ``data/raw/<label>/`` and produce one SampleMetadata per file."""
    raise NotImplementedError


def save_metadata(rows: list[SampleMetadata], path: Path) -> None:
    """Write metadata rows to CSV."""
    raise NotImplementedError


def load_metadata(path: Path) -> list[SampleMetadata]:
    """Load and validate metadata.csv."""
    raise NotImplementedError
