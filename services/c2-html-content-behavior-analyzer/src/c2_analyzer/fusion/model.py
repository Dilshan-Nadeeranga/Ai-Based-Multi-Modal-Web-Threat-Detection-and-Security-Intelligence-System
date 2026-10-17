"""Save / load the chosen fusion model as a plain-dict bundle (Part 4's convention).

Part 9: Tri-modal fusion + ablation study (Batch A, task 3).

    models/fusion/<version>/fusion.joblib     the bundle (git-ignored)
    models/fusion/<version>/model_card.json   arms + their model versions, strategy, params,
                                              CV / test metrics, FPR threshold (tracked)
    models/fusion/<version>/label_mapping.json

A bundle is a dict of plain values + fitted sklearn / XGBoost estimators, never a pickled
instance of our own classes, so loading it does not depend on how fusion/strategies.py
looks later. ``restore`` rebuilds a ready-to-predict strategy from it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np

from c2_analyzer.fusion.strategies import (
    HybridFusion,
    MeanFusion,
    StackingFusion,
    WeightedFusion,
)

BUNDLE_NAME = "fusion.joblib"


def to_bundle(model, labels: list[str], text_arms: list[str], **extra) -> dict[str, Any]:
    bundle: dict[str, Any] = {
        "strategy": model.name,
        "arms": list(model.arms),
        "text_arms": list(text_arms),
        "labels": list(labels),
        "params": model.params(),
    }
    if model.name in ("mean", "weighted"):
        bundle["weights"] = model.weights()
    elif model.name == "stacking":
        bundle.update(estimator=model.estimator, columns=list(model.columns))
    elif model.name == "hybrid":
        bundle.update(
            estimator=model.estimator,
            all_columns=list(model.all_columns),
            columns=list(model.columns),
            dropped=list(model.dropped),
            xgb_params=dict(model.xgb_params),
        )
    else:
        raise ValueError(f"cannot save strategy {model.name!r}")
    bundle.update(extra)
    return bundle


def restore(bundle: dict[str, Any]):
    """A fitted strategy object from a bundle (no training)."""
    name, labels = bundle["strategy"], bundle["labels"]
    if name == "mean":
        model = MeanFusion()
    elif name == "weighted":
        model = WeightedFusion(float(bundle["params"].get("grid_step", 0.1)))
        model.w = np.array([bundle["weights"][arm] for arm in bundle["arms"]])
    elif name == "stacking":
        model = StackingFusion(float(bundle["params"]["C"]))
        model.estimator, model.columns = bundle["estimator"], list(bundle["columns"])
    elif name == "hybrid":
        model = HybridFusion(bundle["xgb_params"])
        model.estimator = bundle["estimator"]
        model.all_columns, model.columns = list(bundle["all_columns"]), list(bundle["columns"])
        model.dropped = list(bundle["dropped"])
        model._index = [model.all_columns.index(c) for c in model.columns]
    else:
        raise ValueError(f"unknown fusion strategy {name!r}")
    model.arms = list(bundle["arms"])
    model.n_classes = len(labels)
    return model


def save_bundle(bundle: dict[str, Any], folder: Path) -> Path:
    path = Path(folder) / BUNDLE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".joblib.tmp")
    joblib.dump(bundle, temp)
    temp.replace(path)
    return path


def load_bundle(folder: Path) -> dict[str, Any] | None:
    """The saved bundle (None if there is none). Only load files this project wrote."""
    path = Path(folder) / BUNDLE_NAME
    return joblib.load(path) if path.is_file() else None
