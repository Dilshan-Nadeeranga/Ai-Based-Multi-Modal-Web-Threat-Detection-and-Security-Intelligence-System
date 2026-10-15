"""Train the three DOM baselines: Logistic Regression, Random Forest, XGBoost.

Part 4: DOM baseline classifier (tasks 4-6).

For each model:
1. every point of its small grid (configs/dom_baseline.yaml) is scored by
   grouped stratified 5-fold CV over train+val (data/splits/<v>/cv_folds.csv);
2. the point with the best MEAN macro-F1 wins (ties: the earlier, i.e. simpler,
   grid point);
3. it is refit on all of train+val and saved as a bundle
   (models/dom_baseline/<version>/<model>.joblib).
The test split is not touched here at all - see evaluate.py.

Why (viva):
- **Grouped CV instead of one validation split:** with ~240 pages a single
  15 % validation split holds only ~40 pages, so one lucky/unlucky page moves
  macro-F1 by several points. Five folds use every train+val page for
  validation once and give a mean +/- std. The folds are grouped by cluster
  (no near-duplicate in both the fitting and the scoring part).
- **Class balance:** benign has ~2x the pages of malware_delivery. Without
  re-weighting, a model gains most by being good at benign. LogReg uses
  class_weight="balanced" (weight = n / (k * n_class)), Random Forest
  "balanced_subsample" (the same, recomputed inside each tree's bootstrap
  sample), XGBoost has no class_weight so it gets the same balanced weights as
  per-sample weights.
- **Why these three:** LogReg is the linear reference (and its standardized
  coefficients are directly interpretable); Random Forest and XGBoost are the
  usual strong models for tabular features (non-linear, no scaling needed).
- **Reproducible:** every random choice uses the project seed (42); n_jobs only
  uses threads inside the model (safe on Windows, same results).
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import ParameterGrid
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight
from tqdm import tqdm
from xgboost import XGBClassifier

from c2_analyzer.classifiers.dom_baseline.common import (
    MODEL_NAMES,
    BaselineConfig,
    bundle_path,
    library_versions,
    model_dir,
    save_bundle,
)
from c2_analyzer.classifiers.dom_baseline.data import DomDataset, label_mapping
from c2_analyzer.classifiers.dom_baseline.evaluate import compute_metrics, summarize_folds
from c2_analyzer.utils.io import write_json


def build_model(name: str, params: dict[str, Any], seed: int, n_jobs: int, n_classes: int):
    """An untrained estimator (fixed settings from the config + one grid point)."""
    if name == "logreg":
        # lbfgs fits ONE softmax (multinomial) model over all classes, not k one-vs-rest models
        return Pipeline(
            [
                ("scale", StandardScaler()),  # coefficients become comparable across features
                ("model", LogisticRegression(random_state=seed, **params)),
            ]
        )
    if name == "random_forest":
        return RandomForestClassifier(random_state=seed, n_jobs=n_jobs, **params)
    if name == "xgboost":
        params = dict(params)
        if n_classes == 2:  # softprob needs >= 3 classes; same model, binary objective
            params.update(objective="binary:logistic", eval_metric="logloss")
        return XGBClassifier(random_state=seed, n_jobs=n_jobs, verbosity=0, **params)
    raise ValueError(f"unknown model {name!r}; expected one of {MODEL_NAMES}")


def fit_model(name: str, estimator, X: np.ndarray, y: np.ndarray):
    """Fit; XGBoost gets balanced per-sample weights (it has no class_weight)."""
    if name == "xgboost":
        estimator.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        estimator.fit(X, y)
    return estimator


def grid_points(config: BaselineConfig, name: str) -> list[dict[str, Any]]:
    """Fixed settings + each grid combination (in a stable order)."""
    section = config.models[name]
    fixed = dict(section.get("fixed") or {})
    grid = section.get("grid") or {}
    points = list(ParameterGrid(grid)) if grid else [{}]
    return [{**fixed, **point} for point in points]


def cross_validate(
    name: str, params: dict[str, Any], dataset: DomDataset, config: BaselineConfig
) -> tuple[list[dict], np.ndarray, np.ndarray]:
    """(metrics per fold, out-of-fold predictions, out-of-fold probabilities) over train+val."""
    pool = dataset.rows("train", "val")
    X = pool[dataset.features].to_numpy(dtype=float)
    y = pool["y"].to_numpy(dtype=int)
    folds = pool["fold"].to_numpy(dtype=int)
    k = len(dataset.labels)
    predictions = np.full(len(y), -1)
    probabilities = np.zeros((len(y), k))
    results = []
    for fold in sorted(set(folds.tolist())):
        held_out = folds == fold
        estimator = build_model(name, params, config.seed, config.jobs(name), k)
        fit_model(name, estimator, X[~held_out], y[~held_out])
        proba = _proba(estimator, X[held_out], k)
        predicted = proba.argmax(axis=1)
        predictions[held_out] = predicted
        probabilities[held_out] = proba
        results.append(compute_metrics(y[held_out], predicted, proba, dataset.labels))
    return results, predictions, probabilities


def _proba(estimator, X: np.ndarray, n_classes: int) -> np.ndarray:
    """predict_proba with one column per class index 0..k-1 (even if a fold missed a class)."""
    raw = estimator.predict_proba(X)
    classes = list(getattr(estimator, "classes_", range(raw.shape[1])))
    proba = np.zeros((len(X), n_classes))
    for column, cls in enumerate(classes):
        proba[:, int(cls)] = raw[:, column]
    return proba


def train_model(
    name: str, dataset: DomDataset, config: BaselineConfig, show_progress: bool = True
) -> dict[str, Any]:
    """Grid search on CV, refit the winner on train+val; returns the bundle (not saved)."""
    started = time.perf_counter()
    grid, runs = [], []
    points = grid_points(config, name)
    for params in tqdm(points, desc=config.display_name(name), disable=not show_progress):
        run = cross_validate(name, params, dataset, config)
        runs.append(run)  # kept, so the winner's CV need not be recomputed
        summary = summarize_folds(run[0])
        grid.append(
            {
                "params": params,
                "mean_macro_f1": summary["mean"]["macro_f1"],
                "std_macro_f1": summary["std"]["macro_f1"],
            }
        )
    # best mean macro-F1; on a tie the earlier grid point (max() keeps the first maximum)
    best_index = max(range(len(grid)), key=lambda i: round(grid[i]["mean_macro_f1"], 10))
    best = grid[best_index]["params"]
    folds, oof_pred, oof_proba = runs[best_index]

    k = len(dataset.labels)
    estimator = build_model(name, best, config.seed, config.jobs(name), k)
    fit_model(name, estimator, dataset.X("train", "val"), dataset.y("train", "val"))
    pool = dataset.rows("train", "val")
    return {
        "estimator": estimator,
        "model": name,
        "display_name": config.display_name(name),
        "params": best,
        "features": list(dataset.features),
        "labels": list(dataset.labels),
        "cv": {
            **summarize_folds(folds),
            "folds": folds,
            "out_of_fold": {
                "sample_id": pool["sample_id"].tolist(),
                "predicted": oof_pred.tolist(),
                "probabilities": np.round(oof_proba, 6).tolist(),
            },
        },
        "grid": grid,
        "best_grid_index": best_index,
        "split_fingerprint": dataset.split_info.get("split_fingerprint"),
        "feature_set_version": dataset.feature_set_version,
        "dictionary_hash": dataset.dictionary_hash,
        "seed": config.seed,
        "trained_on": "train+val",
        "n_train": int(len(pool)),
        "training_seconds": round(time.perf_counter() - started, 2),
        "trained_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "library_versions": library_versions(),
    }


def train_all(
    dataset: DomDataset,
    config: BaselineConfig,
    models: list[str] | None = None,
    show_progress: bool = True,
) -> dict[str, dict[str, Any]]:
    """Train + save the chosen models; also writes label_mapping.json and features.json."""
    folder = model_dir(config, dataset.version)
    excluded = dataset.split_info.get("excluded_classes", {})
    write_json(label_mapping(dataset.labels, excluded), folder / "label_mapping.json")
    write_json(
        {
            "feature_set_version": dataset.feature_set_version,
            "dictionary_hash": dataset.dictionary_hash,
            "features": dataset.features,
            "dropped": dataset.dropped,
            "split_fingerprint": dataset.split_info.get("split_fingerprint"),
        },
        folder / "features.json",
    )
    bundles = {}
    for name in models or list(MODEL_NAMES):
        bundle = train_model(name, dataset, config, show_progress)
        save_bundle(bundle, bundle_path(config, dataset.version, name))
        bundles[name] = bundle
    return bundles
