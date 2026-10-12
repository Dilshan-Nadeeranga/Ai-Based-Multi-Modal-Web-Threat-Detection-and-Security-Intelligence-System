"""Load DOM features, encode labels, split.

Part 4: DOM baseline classifier (LogReg / RandomForest / XGBoost).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def load_features(features_path: Path, splits_dir: Path) -> dict[str, Any]:
    """Return X/y for train/val/test using the Part 1 splits."""
    raise NotImplementedError


def encode_labels(labels: list[str]) -> list[int]:
    """Map label names to ids from configs/labels.yaml."""
    raise NotImplementedError
