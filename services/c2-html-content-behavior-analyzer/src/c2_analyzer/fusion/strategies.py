"""The four fusion strategies, one interface: fit on some pages, predict probabilities.

Part 9: Tri-modal fusion + ablation study (Batch A, task 3).

    a) mean      late fusion: plain average of the arms' probabilities (nothing learnt)
    b) weighted  late fusion: weighted average; the weights (a coarse grid over the simplex,
                 step 0.1, sum = 1) are the ones with the best CV macro-F1 on the pages
                 it is fit on
    c) stacking  Logistic Regression (multinomial, class_weight balanced) on the
                 concatenated OOF probabilities of the arms
    d) hybrid    early + late: XGBoost on [DOM features + behavior features + text-arm
                 OOF probabilities]; constant / |r| > 0.98 features dropped on the pages it
                 is fit on only (Part 4's clean_features), balanced sample weights

How they are scored (viva): every strategy is a "model" that is FIT on some pages and
PREDICTS others. ``cross_validate`` fits it on 4 of the shared grouped folds and predicts
the 5th, for each fold - so even the weights of (b) and the LR of (c) are chosen without
the pages they are scored on. Its inputs are the arms' OOF probabilities (oof.py), never
probabilities of a model that saw the page. The final fusion model is then fit on all of
train+val and predicts the test pages once.

Known limitation (stated in the report): the arm OOF probabilities of the fusion's
training folds came from arm models that saw the fusion's held-out fold; a fully nested
CV would retrain every arm inside every fusion fold (25 XLM-R fine-tunings). The usual
stacking practice accepts this; the one-shot test score is not affected.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from c2_analyzer.classifiers.dom_baseline.data import clean_features
from c2_analyzer.classifiers.dom_baseline.evaluate import compute_metrics


@dataclass
class FusionInputs:
    """What a strategy sees for a set of pages (rows aligned across arms)."""

    arms: list[str]  # the arms of this ablation row, in ARM_ORDER
    probs: dict[str, np.ndarray]  # arm -> (n, k) probabilities
    labels: list[str]
    text_arms: list[str] = field(default_factory=list)  # arms that only give probabilities
    features: np.ndarray | None = None  # (n, f) raw tabular features (hybrid only)
    feature_names: list[str] = field(default_factory=list)  # "dom.node_count", ...

    @property
    def n(self) -> int:
        return len(next(iter(self.probs.values()))) if self.probs else len(self.features)

    def take(self, index) -> FusionInputs:
        index = np.asarray(index)
        return FusionInputs(
            arms=self.arms,
            probs={arm: p[index] for arm, p in self.probs.items()},
            labels=self.labels,
            text_arms=self.text_arms,
            features=None if self.features is None else self.features[index],
            feature_names=self.feature_names,
        )

    def stacked(self, arms: list[str]) -> tuple[np.ndarray, list[str]]:
        """(n, len(arms) * k) concatenated probabilities + column names 'arm.p_class'."""
        columns = [f"{arm}.p_{label}" for arm in arms for label in self.labels]
        if not arms:
            return np.zeros((self.n, 0)), []
        return np.hstack([self.probs[arm] for arm in arms]), columns


def macro_f1(y: np.ndarray, proba: np.ndarray, n_classes: int) -> float:
    return float(
        f1_score(
            y, proba.argmax(axis=1), labels=list(range(n_classes)), average="macro", zero_division=0
        )
    )


def _full_proba(estimator, X: np.ndarray, n_classes: int) -> np.ndarray:
    """predict_proba with one column per class 0..k-1 (a class unseen in training gets 0)."""
    raw = estimator.predict_proba(X)
    proba = np.zeros((len(X), n_classes))
    for column, cls in enumerate(estimator.classes_):
        proba[:, int(cls)] = raw[:, column]
    return proba


# ---- the strategies ------------------------------------------------------------------------


class ArmOnly:
    """A single arm as a 'strategy' (its OOF probabilities as they are) - ablation rows."""

    name = "single"

    def __init__(self, arm: str) -> None:
        self.arm = arm

    def fit(self, inputs: FusionInputs, y: np.ndarray, folds: np.ndarray) -> ArmOnly:
        return self

    def predict_proba(self, inputs: FusionInputs) -> np.ndarray:
        return inputs.probs[self.arm]

    def params(self) -> dict[str, Any]:
        return {"arm": self.arm}


class MeanFusion:
    """(a) every arm counts the same: p = mean_a p_a."""

    name = "mean"

    def fit(self, inputs: FusionInputs, y: np.ndarray, folds: np.ndarray) -> MeanFusion:
        self.arms = list(inputs.arms)
        return self

    def weights(self) -> dict[str, float]:
        return {arm: 1 / len(self.arms) for arm in self.arms}

    def predict_proba(self, inputs: FusionInputs) -> np.ndarray:
        return np.mean([inputs.probs[arm] for arm in self.arms], axis=0)

    def params(self) -> dict[str, Any]:
        return {"weights": self.weights()}


def simplex_grid(n_arms: int, step: float) -> list[tuple[float, ...]]:
    """Every weight vector with entries in {0, step, 2*step, ..., 1} that sums to 1, plus
    the equal weights (1/3 is not on a 0.1 grid; "weighted" must be able to pick "mean")."""
    units = int(round(1 / step))
    points = [tuple(1 / n_arms for _ in range(n_arms))]
    for combo in itertools.product(range(units + 1), repeat=n_arms):
        if sum(combo) == units:
            point = tuple(c / units for c in combo)
            if not np.allclose(point, points[0]):
                points.append(point)
    return points


class WeightedFusion:
    """(b) p = sum_a w_a p_a with w on the simplex, chosen by CV macro-F1 on the fit pages.

    The pages' probabilities are already OOF, so scoring a weight vector on them IS a
    cross-validated score (mean macro-F1 over the folds present). Ties -> the higher
    pooled macro-F1, then the weights closest to equal (the simpler explanation)."""

    name = "weighted"

    def __init__(self, step: float = 0.1) -> None:
        self.step = step

    def fit(self, inputs: FusionInputs, y: np.ndarray, folds: np.ndarray) -> WeightedFusion:
        self.arms = list(inputs.arms)
        k = len(inputs.labels)
        stacked = np.stack([inputs.probs[arm] for arm in self.arms])  # (arms, n, k)
        uniform = np.full(len(self.arms), 1 / len(self.arms))
        best_key, best = None, None
        for point in simplex_grid(len(self.arms), self.step):
            w = np.asarray(point)
            fused = np.tensordot(w, stacked, axes=1)
            fold_scores = [macro_f1(y[folds == f], fused[folds == f], k) for f in np.unique(folds)]
            key = (
                round(float(np.mean(fold_scores)), 10),
                round(macro_f1(y, fused, k), 10),
                -round(float(np.linalg.norm(w - uniform)), 10),
            )
            if best_key is None or key > best_key:
                best_key, best = key, w
        self.w = best
        self.cv_score = best_key[0]
        return self

    def weights(self) -> dict[str, float]:
        return {arm: float(w) for arm, w in zip(self.arms, self.w, strict=True)}

    def predict_proba(self, inputs: FusionInputs) -> np.ndarray:
        return np.tensordot(self.w, np.stack([inputs.probs[arm] for arm in self.arms]), axes=1)

    def params(self) -> dict[str, Any]:
        return {"weights": self.weights(), "grid_step": self.step}


class StackingFusion:
    """(c) multinomial Logistic Regression on the concatenated arm probabilities.

    Its coefficients say how much each arm's vote for each class moves the final
    decision - the explanation of the stacker (explain.py)."""

    name = "stacking"

    def __init__(self, C: float = 1.0, max_iter: int = 5000, seed: int = 42) -> None:  # noqa: N803
        self.C, self.max_iter, self.seed = C, max_iter, seed

    def fit(self, inputs: FusionInputs, y: np.ndarray, folds: np.ndarray) -> StackingFusion:
        self.arms = list(inputs.arms)
        X, self.columns = inputs.stacked(self.arms)
        self.estimator = LogisticRegression(
            C=self.C, class_weight="balanced", max_iter=self.max_iter, random_state=self.seed
        ).fit(X, y)
        self.n_classes = len(inputs.labels)
        return self

    def predict_proba(self, inputs: FusionInputs) -> np.ndarray:
        X, _ = inputs.stacked(self.arms)
        return _full_proba(self.estimator, X, self.n_classes)

    def params(self) -> dict[str, Any]:
        return {"C": self.C, "class_weight": "balanced", "inputs": self.columns}


class HybridFusion:
    """(d) XGBoost on raw DOM / behavior features + text-arm probabilities.

    Feature cleaning (constant, |r| > threshold) is decided on the pages it is FIT on -
    inside CV that is the training folds only, exactly like Part 4 decides it on train."""

    name = "hybrid"

    def __init__(
        self, params: dict[str, Any], correlation_threshold: float = 0.98, seed: int = 42
    ) -> None:
        self.xgb_params = dict(params)
        self.correlation_threshold = correlation_threshold
        self.seed = seed

    def _matrix(self, inputs: FusionInputs) -> tuple[np.ndarray, list[str]]:
        text, text_columns = inputs.stacked(inputs.text_arms)
        if inputs.features is None:
            return text, text_columns
        return np.hstack([inputs.features, text]), list(inputs.feature_names) + text_columns

    def fit(self, inputs: FusionInputs, y: np.ndarray, folds: np.ndarray) -> HybridFusion:
        import pandas as pd

        self.arms = list(inputs.arms)
        X, names = self._matrix(inputs)
        kept, dropped = clean_features(
            pd.DataFrame(X, columns=names), names, self.correlation_threshold
        )
        self.all_columns, self.columns, self.dropped = names, kept, dropped
        self._index = [names.index(name) for name in kept]
        self.n_classes = len(inputs.labels)
        params = dict(self.xgb_params)
        if self.n_classes == 2:
            params.update(objective="binary:logistic", eval_metric="logloss")
        self.estimator = XGBClassifier(random_state=self.seed, n_jobs=1, verbosity=0, **params)
        self.estimator.fit(X[:, self._index], y, sample_weight=compute_sample_weight("balanced", y))
        return self

    def design(self, inputs: FusionInputs) -> np.ndarray:
        """The model input (cleaned columns) of some pages."""
        X, names = self._matrix(inputs)
        if names != self.all_columns:
            raise ValueError("hybrid inputs have other columns than at fit time")
        return X[:, self._index]

    def predict_proba(self, inputs: FusionInputs) -> np.ndarray:
        return _full_proba(self.estimator, self.design(inputs), self.n_classes)

    def params(self) -> dict[str, Any]:
        return {
            **self.xgb_params,
            "features_in": len(self.all_columns),
            "features_used": len(self.columns),
            "dropped": len(self.dropped),
        }


def make_strategy(name: str, config, seed: int = 42, correlation_threshold: float = 0.98):
    """A fresh, unfitted strategy from configs/fusion.yaml."""
    settings = config.strategy(name)
    if name == "mean":
        return MeanFusion()
    if name == "weighted":
        return WeightedFusion(float(settings.get("step", 0.1)))
    if name == "stacking":
        return StackingFusion(
            float(settings.get("C", 1.0)), int(settings.get("max_iter", 5000)), seed
        )
    if name == "hybrid":
        return HybridFusion(settings["params"], correlation_threshold, seed)
    raise ValueError(f"unknown fusion strategy {name!r}")


# ---- grouped CV of a strategy ----------------------------------------------------------------


def cross_validate(
    make, inputs: FusionInputs, y: np.ndarray, folds: np.ndarray
) -> tuple[list[dict], np.ndarray]:
    """(metrics per fold, fused out-of-fold probabilities) - fit on 4 folds, predict the 5th.

    ``make()`` returns a fresh strategy; ``inputs``/``y``/``folds`` are the train+val pages.
    """
    k = len(inputs.labels)
    fused = np.zeros((len(y), k))
    results = []
    for fold in sorted(np.unique(folds).tolist()):
        held = folds == fold
        model = make().fit(inputs.take(~held), y[~held], folds[~held])
        fused[held] = model.predict_proba(inputs.take(held))
        results.append(
            compute_metrics(y[held], fused[held].argmax(axis=1), fused[held], inputs.labels)
        )
    return results, fused
