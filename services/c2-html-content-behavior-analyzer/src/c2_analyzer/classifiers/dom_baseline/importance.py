"""Feature importance (model-native and SHAP).

Part 4: DOM baseline classifier (LogReg / RandomForest / XGBoost).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def feature_importance(model: Any, feature_names: list[str]) -> dict[str, float]:
    """Model-native importances / coefficients."""
    raise NotImplementedError


def shap_summary(model: Any, X: Any, path: Path) -> None:
    """Save a SHAP summary plot."""
    raise NotImplementedError
