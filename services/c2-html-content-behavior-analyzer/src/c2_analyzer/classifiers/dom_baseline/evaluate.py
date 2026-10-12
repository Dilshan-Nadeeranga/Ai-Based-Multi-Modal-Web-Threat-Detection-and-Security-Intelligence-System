"""Precision/recall/F1 and confusion matrix for DOM baselines.

Part 4: DOM baseline classifier (LogReg / RandomForest / XGBoost).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def evaluate(model: Any, X: Any, y: Any) -> dict[str, Any]:
    """Per-class and macro precision/recall/F1 plus confusion matrix."""
    raise NotImplementedError


def plot_confusion_matrix(cm: Any, labels: list[str], path: Path) -> None:
    """Save a confusion-matrix figure to reports/figures/."""
    raise NotImplementedError
