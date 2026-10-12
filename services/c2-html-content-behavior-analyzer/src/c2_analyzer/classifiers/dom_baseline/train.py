"""Train LogReg, RandomForest and XGBoost baselines.

Part 4: DOM baseline classifier (LogReg / RandomForest / XGBoost).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

MODEL_NAMES: tuple[str, ...] = ("logistic_regression", "random_forest", "xgboost")


def build_model(name: str, params: dict[str, Any]) -> Any:
    """Instantiate an untrained model by name."""
    raise NotImplementedError


def train_all(data: dict[str, Any], output_dir: Path) -> dict[str, Path]:
    """Train every baseline and save it (joblib); return model paths."""
    raise NotImplementedError
