"""Why the fusion model decided: per-arm (and per-feature) contributions.

Part 9: Tri-modal fusion + ablation study (Batch A, task 4 + inspector).

- mean / weighted: the fused score of class c is sum_a w_a * p_a(c), so arm a contributes
  exactly w_a * p_a(c) - the global explanation is the weights themselves.
- stacking (LR): the score (logit) of class c is b_c + sum_j coef[c, j] * x_j over the
  arms' probability columns x_j; an arm's contribution = the sum over its own columns.
  Globally: mean |coef| per arm, and the coefficient table.
- hybrid (XGBoost): TreeExplainer SHAP values (log-odds, Part 4's ``shap_values``) per
  feature; an arm's contribution = the sum over its features ("dom.*", "behavior.*") or
  its probability columns ("text_tfidf.*"). Globally: mean |SHAP| on the test pages.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from matplotlib.figure import Figure

from c2_analyzer.fusion.strategies import FusionInputs


def arm_of(column: str) -> str:
    """'dom.node_count' -> 'dom', 'text_tfidf.p_benign' -> 'text_tfidf'."""
    return column.split(".", 1)[0]


def _shap(model, X: np.ndarray) -> np.ndarray:
    from c2_analyzer.classifiers.dom_baseline.importance import shap_values

    return shap_values(model.estimator, X, model.n_classes)  # (pages, features, classes)


def global_explanation(model, inputs: FusionInputs, top: int = 15) -> dict:
    """Arm shares (sum to 1) + details, on ``inputs`` (the test pages for the hybrid)."""
    if model.name in ("mean", "weighted"):
        weights = model.weights()
        return {"strategy": model.name, "method": "weights", "arm_share": weights}
    if model.name == "stacking":
        coef = model.estimator.coef_  # (classes, columns)
        per_column = np.abs(coef).mean(axis=0)
        arms = {}
        for column, value in zip(model.columns, per_column, strict=True):
            arms[arm_of(column)] = arms.get(arm_of(column), 0.0) + float(value)
        total = sum(arms.values()) or 1.0
        classes = [inputs.labels[int(c)] for c in model.estimator.classes_]
        return {
            "strategy": "stacking",
            "method": "LR coefficients (mean |coef| over classes, summed per arm)",
            "arm_share": {arm: value / total for arm, value in arms.items()},
            "coefficients": {
                cls: dict(zip(model.columns, map(float, row), strict=True))
                for cls, row in zip(classes, coef, strict=True)
            },
        }
    if model.name == "hybrid":
        values = _shap(model, model.design(inputs))
        per_feature = np.abs(values).mean(axis=0)  # (features, classes)
        overall = per_feature.sum(axis=1)
        arms = {}
        for column, value in zip(model.columns, overall, strict=True):
            arms[arm_of(column)] = arms.get(arm_of(column), 0.0) + float(value)
        total = sum(arms.values()) or 1.0
        order = np.argsort(-overall)[:top]
        return {
            "strategy": "hybrid",
            "method": "SHAP (TreeExplainer, mean |SHAP| over the test pages, summed over classes)",
            "arm_share": {arm: value / total for arm, value in arms.items()},
            "top_features": [
                {
                    "feature": model.columns[i],
                    "arm": arm_of(model.columns[i]),
                    "mean_abs_shap": float(overall[i]),
                    "per_class": {
                        label: float(per_feature[i, j]) for j, label in enumerate(inputs.labels)
                    },
                }
                for i in order
            ],
        }
    raise ValueError(f"no explanation for strategy {model.name!r}")


def page_drivers(model, inputs: FusionInputs, class_index: int, top: int = 5) -> dict:
    """Contributions towards ``class_index`` for ONE page (inputs with a single row)."""
    if model.name in ("mean", "weighted"):
        weights = model.weights()
        arms = {arm: float(weights[arm] * inputs.probs[arm][0, class_index]) for arm in model.arms}
        return {"method": "weight x arm probability", "arms": arms, "features": []}
    if model.name == "stacking":
        X, columns = inputs.stacked(model.arms)
        row = list(model.estimator.classes_).index(class_index)
        terms = model.estimator.coef_[row] * X[0]
        arms = {}
        for column, value in zip(columns, terms, strict=True):
            arms[arm_of(column)] = arms.get(arm_of(column), 0.0) + float(value)
        order = np.argsort(-np.abs(terms))[:top]
        return {
            "method": "LR coefficient x arm probability (logit)",
            "arms": arms,
            "features": [
                {"feature": columns[i], "value": float(X[0, i]), "contribution": float(terms[i])}
                for i in order
            ],
        }
    if model.name == "hybrid":
        X = model.design(inputs)
        values = _shap(model, X)[0, :, class_index]
        arms = {}
        for column, value in zip(model.columns, values, strict=True):
            arms[arm_of(column)] = arms.get(arm_of(column), 0.0) + float(value)
        order = np.argsort(-np.abs(values))[:top]
        return {
            "method": "SHAP (log-odds)",
            "arms": arms,
            "features": [
                {
                    "feature": model.columns[i],
                    "value": float(X[0, i]),
                    "contribution": float(values[i]),
                }
                for i in order
            ],
        }
    raise ValueError(f"no explanation for strategy {model.name!r}")


def plot_explanation(explanation: dict, displays: dict[str, str], title: str, path: Path) -> Path:
    """Left: share of each arm; right: top SHAP features (hybrid) or LR coefficients."""
    shares = explanation["arm_share"]
    detail = explanation.get("top_features") or explanation.get("coefficients")
    figure = Figure(figsize=(12 if detail else 6, 4.8), layout="constrained")
    axes = figure.subplots(1, 2 if detail else 1, squeeze=False)[0]
    arms = list(shares)
    axes[0].barh([displays.get(a, a) for a in arms][::-1], [shares[a] for a in arms][::-1])
    axes[0].set_xlabel("share of the fused decision")
    axes[0].set_title(explanation["method"], fontsize=9)
    if explanation.get("top_features"):
        rows = explanation["top_features"][::-1]
        axes[1].barh([r["feature"] for r in rows], [r["mean_abs_shap"] for r in rows])
        axes[1].tick_params(axis="y", labelsize=7)
        axes[1].set_xlabel("mean |SHAP| (log-odds), summed over classes")
        axes[1].set_title("top features")
    elif explanation.get("coefficients"):
        coefficients = explanation["coefficients"]
        classes = list(coefficients)
        columns = list(next(iter(coefficients.values())))
        matrix = np.array([[coefficients[c][col] for col in columns] for c in classes])
        limit = float(np.abs(matrix).max()) or 1.0
        image = axes[1].imshow(matrix, cmap="RdBu_r", vmin=-limit, vmax=limit, aspect="auto")
        axes[1].set_yticks(range(len(classes)), classes)
        axes[1].set_xticks(range(len(columns)), columns, rotation=90, fontsize=6)
        axes[1].set_title("LR coefficients (row = predicted class)")
        figure.colorbar(image, ax=axes[1], shrink=0.8)
    figure.suptitle(title)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=130)
    return path
