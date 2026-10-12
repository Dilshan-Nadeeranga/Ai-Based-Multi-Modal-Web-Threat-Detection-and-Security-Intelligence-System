"""Dataset statistics (class/language balance) and train/val/test splitting.

Part 1: Multilingual dataset preparation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def compute_statistics(metadata_path: Path) -> dict[str, Any]:
    """Counts per label, per language and label x language."""
    raise NotImplementedError


def split_dataset(
    metadata_path: Path, splits_dir: Path, ratios=(0.70, 0.15, 0.15), seed: int = 42
) -> None:
    """Stratified train/val/test split written to ``splits_dir``."""
    raise NotImplementedError
