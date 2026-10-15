"""Predict one page with the trained DOM baselines (+ the features behind it).

Part 4: DOM baseline classifier. Used by ``train_dom_baseline.py predict`` and
the inspector's "DOM baseline prediction" card.

Input is the Part 3 feature dict of the page (``DomResult.features``), so a
prediction uses exactly the vector layout the model was trained on: the
bundle's ``features`` list picks and orders the columns (dropped features are
simply not used). The feature dictionary hash is checked - features made with
another dictionary would silently mean something else.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from c2_analyzer.classifiers.dom_baseline.common import MODEL_NAMES
from c2_analyzer.classifiers.dom_baseline.importance import contributions
from c2_analyzer.schemas.dom_baseline import (
    DomPrediction,
    FeatureContribution,
    ModelPrediction,
)


class PredictionError(ValueError):
    """The page's features do not fit the trained models."""


def feature_row(features: dict[str, float], bundle: dict[str, Any]) -> np.ndarray:
    """The model input (1 x n) in the bundle's feature order."""
    missing = [name for name in bundle["features"] if name not in features]
    if missing:
        raise PredictionError(f"features missing for the model: {missing[:5]}")
    return np.array([[float(features[name]) for name in bundle["features"]]])


def best_model(bundles: dict[str, dict[str, Any]]) -> str:
    """The model with the highest mean CV macro-F1 (never chosen on test)."""
    return max(
        (name for name in MODEL_NAMES if name in bundles),
        key=lambda name: bundles[name]["cv"]["mean"]["macro_f1"],
    )


def predict_features(
    features: dict[str, float],
    bundles: dict[str, dict[str, Any]],
    *,
    version: str,
    dictionary_hash: str,
    excluded_classes: dict[str, int] | None = None,
    explain: str | None = None,
    top: int = 5,
    sample_id: str | None = None,
) -> DomPrediction:
    """Probabilities from every model + the top contributions of ``explain`` (default: best)."""
    if not bundles:
        raise PredictionError(f"no trained DOM baseline for {version}")
    first = next(iter(bundles.values()))
    if first["dictionary_hash"] != dictionary_hash:
        raise PredictionError(
            "the models were trained on features from another feature dictionary - retrain"
        )
    labels = first["labels"]
    answers = []
    for name in MODEL_NAMES:
        if name not in bundles:
            continue
        bundle = bundles[name]
        proba = bundle["estimator"].predict_proba(feature_row(features, bundle))[0]
        full = np.zeros(len(labels))
        for column, cls in enumerate(bundle["estimator"].classes_):
            full[int(cls)] = proba[column]
        full = full / full.sum()  # guard against float drift: always sums to 1
        answers.append(
            ModelPrediction(
                model=name,
                display_name=bundle["display_name"],
                predicted=labels[int(full.argmax())],
                probabilities={label: float(p) for label, p in zip(labels, full, strict=True)},
                cv_macro_f1=bundle["cv"]["mean"]["macro_f1"],
            )
        )
    best = best_model(bundles)
    chosen = next(answer for answer in answers if answer.model == best)
    explained = explain if explain in bundles else best
    explained_answer = next(answer for answer in answers if answer.model == explained)
    class_index = labels.index(explained_answer.predicted)
    bundle = bundles[explained]
    pushes = contributions(bundle, feature_row(features, bundle)[0], class_index, top)
    excluded = excluded_classes or {}
    return DomPrediction(
        sample_id=sample_id,
        dataset_version=version,
        feature_set_version=first["feature_set_version"],
        classes=labels,
        excluded_classes=excluded,
        pilot=bool(excluded),
        best_model=best,
        predicted=chosen.predicted,
        probabilities=chosen.probabilities,
        models=answers,
        explained_model=explained,
        contributions=[FeatureContribution(**item) for item in pushes],
    )
