"""DOM feature importance: which structural features the baselines rely on.

Part 4: DOM baseline classifier (task 9).

Methods (top 15 each, shown with the dictionary descriptions, not raw names):
- **Logistic Regression - standardized coefficients per class.** The inputs
  are z-scores, so a coefficient is "change in that class's log-odds per one
  standard deviation of the feature" and coefficients are comparable.
- **Random Forest - impurity importance** (how much the feature's splits
  reduce Gini impurity, from the training data) **and permutation importance
  on test** (how much test macro-F1 drops when that feature's values are
  shuffled). Impurity importance favours features with many distinct values;
  permutation importance does not, but is noisier.
- **XGBoost - gain importance** (average loss reduction of the splits on the
  feature) **and SHAP** (TreeExplainer): for every page, how much each feature
  pushes each class's score up or down. The global summary = mean |SHAP| per
  feature and class; the beeswarms show the direction per class.

Caveat (also printed in the report): on a small pilot test split (~40 pages)
permutation importance and SHAP rankings are INDICATIVE only - a feature's
rank can change with a handful of pages. They show what the models use, not
what causes a page to be malicious.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from matplotlib.figure import Figure
from sklearn.inspection import permutation_importance

from c2_analyzer.classifiers.dom_baseline.common import (
    BaselineConfig,
    describe_feature,
    readable_name,
)

CAVEAT = (
    "Permutation importance and SHAP are computed on a small pilot test split; "
    "the rankings are indicative only (a few pages can reorder them)."
)


def _top(scores: dict[str, float], n: int, by_abs: bool = True, source=None) -> list[dict]:
    order = sorted(scores, key=lambda f: -abs(scores[f]) if by_abs else -scores[f])
    return [
        {
            "feature": name,
            "name": readable_name(name, source=source),
            "description": describe_feature(name, source=source),
            "value": float(scores[name]),
        }
        for name in order[:n]
    ]


# ---- per model ----------------------------------------------------------------------------


def logreg_coefficients(bundle: dict[str, Any], n: int, source=None) -> dict[str, list[dict]]:
    """Standardized coefficients per class (binary: one row = the positive class)."""
    model = bundle["estimator"].named_steps["model"]
    features, labels = bundle["features"], bundle["labels"]
    coefficients = model.coef_
    if coefficients.shape[0] == 1:  # binary logistic regression: class 0 = minus class 1
        coefficients = np.vstack([-coefficients[0], coefficients[0]])
    return {
        label: _top(dict(zip(features, coefficients[i], strict=True)), n, source=source)
        for i, label in enumerate(labels)
    }


def forest_importance(
    bundle: dict[str, Any], X_test: np.ndarray, y_test: np.ndarray, config: BaselineConfig
) -> dict[str, list[dict]]:
    """Impurity importance (train) + permutation importance on test (macro-F1 drop)."""
    estimator, features = bundle["estimator"], bundle["features"]
    impurity = dict(zip(features, estimator.feature_importances_, strict=True))
    # n_jobs=1: permutation_importance uses worker processes otherwise (slow to start on Windows)
    permutation = permutation_importance(
        estimator,
        X_test,
        y_test,
        scoring="f1_macro",
        n_repeats=config.permutation_repeats,
        random_state=config.seed,
        n_jobs=1,
    )
    mean = dict(zip(features, permutation.importances_mean, strict=True))
    top_permutation = _top(mean, config.top_n, by_abs=False, source=config.source)
    std = dict(zip(features, permutation.importances_std, strict=True))
    for row in top_permutation:
        row["std"] = float(std[row["feature"]])
    return {
        "impurity": _top(impurity, config.top_n, by_abs=False, source=config.source),
        "permutation_test": top_permutation,
    }


def xgb_gain(bundle: dict[str, Any], n: int, source=None) -> list[dict]:
    """Average gain per split; features never used in a split have gain 0."""
    features = bundle["features"]
    scores = bundle["estimator"].get_booster().get_score(importance_type="gain")
    by_name = {
        features[int(key[1:])] if key.startswith("f") and key[1:].isdigit() else key: value
        for key, value in scores.items()
    }
    gains = {name: float(by_name.get(name, 0.0)) for name in features}
    return _top(gains, n, by_abs=False, source=source)


def shap_values(estimator, X: np.ndarray, n_classes: int) -> np.ndarray:
    """SHAP values as (pages, features, classes) for any tree model (binary is mirrored)."""
    import shap

    values = np.asarray(shap.TreeExplainer(estimator).shap_values(X))
    if values.ndim == 2:  # binary XGBoost: log-odds of class 1; class 0 is the mirror image
        values = np.stack([-values, values], axis=2)
    if values.shape[2] != n_classes:
        raise ValueError(f"SHAP returned {values.shape[2]} classes, expected {n_classes}")
    return values


def shap_summary(bundle: dict[str, Any], X: np.ndarray, n: int, source=None) -> dict[str, Any]:
    """Global SHAP: mean |SHAP| per feature (overall and per class) on the given pages."""
    features, labels = bundle["features"], bundle["labels"]
    values = shap_values(bundle["estimator"], X, len(labels))
    per_class = np.abs(values).mean(axis=0)  # (features, classes)
    overall = per_class.sum(axis=1)
    top = _top(dict(zip(features, overall, strict=True)), n, by_abs=False, source=source)
    for row in top:
        index = features.index(row["feature"])
        row["per_class"] = {label: float(per_class[index, j]) for j, label in enumerate(labels)}
    return {"global": top, "values": values}


# ---- contributions for ONE page (predict / inspector) --------------------------------------


def contributions(
    bundle: dict[str, Any], x: np.ndarray, class_index: int, top: int, source=None
) -> list[dict]:
    """The features that move ``class_index``'s score most for one page.

    Logistic Regression: coefficient x z-score (exact contribution to that
    class's logit). Trees: SHAP values (exact contribution to the score).
    Positive = pushes TOWARDS the class, negative = pushes AWAY from it.
    """
    estimator, features = bundle["estimator"], bundle["features"]
    row = np.asarray(x, dtype=float).reshape(1, -1)
    if bundle["model"] == "logreg":
        z = estimator.named_steps["scale"].transform(row)[0]
        coefficients = estimator.named_steps["model"].coef_
        if coefficients.shape[0] == 1:
            coefficients = np.vstack([-coefficients[0], coefficients[0]])
        scores = coefficients[class_index] * z
        method = "coefficient x z-score"
    else:
        scores = shap_values(estimator, row, len(bundle["labels"]))[0, :, class_index]
        method = "SHAP (TreeExplainer)"
    label = bundle["labels"][class_index]
    order = np.argsort(-np.abs(scores))[:top]
    result = []
    for index in order:
        value = float(scores[index])
        if value == 0.0:
            continue
        direction = "towards" if value > 0 else "away"
        name = features[index]
        feature_value = float(row[0, index])
        shown = f"{feature_value:g}"
        result.append(
            {
                "feature": name,
                "name": readable_name(name, source=source),
                "description": describe_feature(name, source=source),
                "value": feature_value,
                "contribution": value,
                "direction": direction,
                "method": method,
                "text": f"{readable_name(name, source=source)} = {shown} pushes "
                + ("towards " if value > 0 else "away from ")
                + label,
            }
        )
    return result


# ---- figures --------------------------------------------------------------------------------


def _barh(axis, rows: list[dict], title: str, color: str = "#3b6fb6") -> None:
    rows = list(reversed(rows))
    values = [row["value"] for row in rows]
    colors = [color if v >= 0 else "#c0504d" for v in values]
    axis.barh([row["name"] for row in rows], values, color=colors)
    axis.set_title(title, fontsize=10)
    axis.tick_params(axis="y", labelsize=8)
    axis.axvline(0, color="#555", linewidth=0.6)


def plot_bars(rows: list[dict], title: str, xlabel: str, path: Path) -> Path:
    figure = Figure(figsize=(9, 0.32 * max(len(rows), 4) + 1.2), layout="constrained")
    axis = figure.subplots()
    _barh(axis, rows, title)
    axis.set_xlabel(xlabel)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=130)
    return path


def plot_per_class(per_class: dict[str, list[dict]], title: str, xlabel: str, path: Path) -> Path:
    labels = list(per_class)
    height = 0.32 * max(len(rows) for rows in per_class.values()) + 1.4
    figure = Figure(figsize=(9, height * len(labels)), layout="constrained")
    for axis, label in zip(np.atleast_1d(figure.subplots(len(labels), 1)), labels, strict=True):
        _barh(axis, per_class[label], label)
        axis.set_xlabel(xlabel)
    figure.suptitle(title)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=130)
    return path


def plot_shap_global(top: list[dict], labels: list[str], path: Path) -> Path:
    """Stacked bars: mean |SHAP| per feature, split by class (like shap's multi-class bar)."""
    rows = list(reversed(top))
    figure = Figure(figsize=(9, 0.32 * max(len(rows), 4) + 1.4), layout="constrained")
    axis = figure.subplots()
    left = np.zeros(len(rows))
    for label in labels:
        values = np.array([row["per_class"][label] for row in rows])
        axis.barh([row["name"] for row in rows], values, left=left, label=label)
        left += values
    axis.set_xlabel("mean |SHAP value| (log-odds), summed over classes")
    axis.set_title("XGBoost - global SHAP importance (test split)")
    axis.tick_params(axis="y", labelsize=8)
    axis.legend(fontsize=8, loc="lower right")
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=130)
    return path


def plot_shap_beeswarm(
    values: np.ndarray,
    X: np.ndarray,
    features: list[str],
    label: str,
    n: int,
    path: Path,
    source=None,
) -> Path:
    """SHAP's own beeswarm for one class (pyplot-based, so it gets its own figure)."""
    import matplotlib

    matplotlib.use("Agg")  # no window, also on machines without a display
    import matplotlib.pyplot as plt
    import shap

    explanation = shap.Explanation(
        values=values, data=X, feature_names=[readable_name(f, source=source) for f in features]
    )
    plt.figure()
    shap.plots.beeswarm(explanation, max_display=n, show=False, plot_size=(10, 0.4 * n + 1.5))
    plt.title(f"XGBoost SHAP - class {label} (test split)", fontsize=10)
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(path, dpi=130, bbox_inches="tight")
    plt.close("all")
    return path


# ---- everything for one version -------------------------------------------------------------


def compute_importance(
    bundles: dict[str, dict[str, Any]],
    X_test: np.ndarray,
    y_test: np.ndarray,
    config: BaselineConfig,
    figures: Path | None = None,
) -> dict[str, Any]:
    """Importance of every trained model (+ figures if a folder is given)."""
    n = config.top_n
    result: dict[str, Any] = {"caveat": CAVEAT, "top_n": n}
    if "logreg" in bundles:
        coefficients = logreg_coefficients(bundles["logreg"], n, config.source)
        result["logreg"] = {"standardized_coefficients": coefficients}
        if figures:
            plot_per_class(
                coefficients,
                "Logistic Regression - standardized coefficients",
                "coefficient (log-odds per 1 std)",
                figures / "importance_logreg_coefficients.png",
            )
    if "random_forest" in bundles:
        forest = forest_importance(bundles["random_forest"], X_test, y_test, config)
        result["random_forest"] = forest
        if figures:
            plot_bars(
                forest["impurity"],
                "Random Forest - impurity importance",
                "mean decrease in impurity",
                figures / "importance_random_forest_impurity.png",
            )
            plot_bars(
                forest["permutation_test"],
                "Random Forest - permutation importance (test)",
                "macro-F1 drop when shuffled",
                figures / "importance_random_forest_permutation.png",
            )
    if "xgboost" in bundles:
        bundle = bundles["xgboost"]
        gain = xgb_gain(bundle, n, config.source)
        summary = shap_summary(bundle, X_test, n, config.source)
        result["xgboost"] = {"gain": gain, "shap_global": summary["global"]}
        if figures:
            plot_bars(
                gain,
                "XGBoost - gain importance",
                "average gain",
                figures / "importance_xgboost_gain.png",
            )
            plot_shap_global(
                summary["global"], bundle["labels"], figures / "shap_global_xgboost.png"
            )
            for j, label in enumerate(bundle["labels"]):
                plot_shap_beeswarm(
                    summary["values"][:, :, j],
                    X_test,
                    bundle["features"],
                    label,
                    n,
                    figures / f"shap_beeswarm_{label}.png",
                    config.source,
                )
    return result
