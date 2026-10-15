"""Precision / recall / F1, benign false-positive rate, confusion matrices.

Part 4: DOM baseline classifier (tasks 7-8).

The same ``compute_metrics`` is used for every CV fold and for the test split,
so CV and test numbers are directly comparable.

Why these metrics (viva):
- **Macro-F1 is the primary metric.** It is the plain average of the per-class
  F1 scores, so the small malware_delivery class counts as much as the large
  benign class. Accuracy would look good for a model that is only good at the
  majority class.
- **Weighted-F1, accuracy, balanced accuracy** are reported for comparison with
  other papers; **one-vs-rest ROC-AUC (macro)** shows how well the
  probabilities rank pages, independent of the 0.5-style decision.
- **Benign false-positive rate** = (benign test pages predicted as ANY threat)
  / (benign test pages). The proposal's target is <= 2 %: a detector that
  flags real sites is not usable. The flagged sample_ids are listed so they
  can be opened in the inspector.
- **The test split is evaluated ONCE**, after the model and its
  hyperparameters were chosen on CV. If we looked at test scores while
  choosing, test would become a second validation set and the reported number
  would be optimistic. (Re-running ``evaluate`` recomputes the same numbers
  from the same saved models; it does not choose anything.)
- **Per-language results** are shown where the counts allow; with 1-3 Sinhala
  or Tamil test pages they are anecdotes, so they carry a small-n warning.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
from matplotlib.figure import Figure
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    recall_score,
    roc_auc_score,
)

SCALAR_METRICS = (
    "macro_f1",
    "weighted_f1",
    "accuracy",
    "balanced_accuracy",
    "roc_auc_ovr_macro",
    "benign_fpr",
)
BENIGN = "benign"


def benign_fpr(y_true: np.ndarray, y_pred: np.ndarray, benign_index: int) -> float | None:
    """Share of truly benign pages predicted as any threat (None if there is no benign page)."""
    benign = np.asarray(y_true) == benign_index
    if not benign.any():
        return None
    return float((np.asarray(y_pred)[benign] != benign_index).sum() / benign.sum())


def roc_auc(y_true: np.ndarray, proba: np.ndarray | None, n_classes: int) -> float | None:
    """One-vs-rest macro ROC-AUC; None without probabilities or when a class is missing."""
    if proba is None or len(np.unique(y_true)) < n_classes or n_classes < 2:
        return None
    if n_classes == 2:
        return float(roc_auc_score(y_true, proba[:, 1]))
    return float(
        roc_auc_score(y_true, proba, multi_class="ovr", average="macro", labels=range(n_classes))
    )


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    proba: np.ndarray | None,
    labels: list[str],
    present_only: bool = False,
) -> dict:
    """All metrics of one prediction set.

    ``present_only=True`` (per-language subsets) averages over the classes that
    occur in that subset, because a language with no malware page cannot have
    a malware F1.
    """
    y_true, y_pred = np.asarray(y_true, dtype=int), np.asarray(y_pred, dtype=int)
    every = list(range(len(labels)))
    used = sorted(set(y_true.tolist())) if present_only else every
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=every, zero_division=0
    )
    per_class = {
        label: {
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
        }
        for i, label in enumerate(labels)
    }
    benign_index = labels.index(BENIGN) if BENIGN in labels else None
    return {
        "n": int(len(y_true)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=used, average="macro", zero_division=0)),
        "weighted_f1": float(
            f1_score(y_true, y_pred, labels=used, average="weighted", zero_division=0)
        ),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        # balanced accuracy = mean recall over the true classes
        "balanced_accuracy": float(
            recall_score(y_true, y_pred, labels=used, average="macro", zero_division=0)
        ),
        "roc_auc_ovr_macro": None if present_only else roc_auc(y_true, proba, len(labels)),
        "benign_fpr": None if benign_index is None else benign_fpr(y_true, y_pred, benign_index),
        "per_class": per_class,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=every).tolist(),
    }


def summarize_folds(folds: list[dict]) -> dict:
    """{"mean": {...}, "std": {...}} over CV folds (scalar metrics + per-class F1)."""
    mean, std = {}, {}
    for key in SCALAR_METRICS:
        values = [fold[key] for fold in folds if fold.get(key) is not None]
        mean[key] = float(np.mean(values)) if values else None
        std[key] = float(np.std(values)) if values else None
    for label in folds[0]["per_class"] if folds else []:
        values = [fold["per_class"][label]["f1"] for fold in folds]
        mean[f"f1_{label}"] = float(np.mean(values))
        std[f"f1_{label}"] = float(np.std(values))
    return {"mean": mean, "std": std}


def per_language(frame, y_pred: np.ndarray, labels: list[str], min_support: int) -> dict:
    """Test metrics per language (frame = the test rows, same order as y_pred)."""
    result = {}
    y_true = frame["y"].to_numpy(dtype=int)
    languages = frame["language"].to_numpy()
    for language in sorted(set(languages.tolist())):
        mask = languages == language
        metrics = compute_metrics(y_true[mask], y_pred[mask], None, labels, present_only=True)
        result[language] = {
            "n": metrics["n"],
            "accuracy": metrics["accuracy"],
            "macro_f1": metrics["macro_f1"],
            "benign_fpr": metrics["benign_fpr"],
            "labels": {
                label: int((y_true[mask] == i).sum())
                for i, label in enumerate(labels)
                if (y_true[mask] == i).any()
            },
            "small_n": metrics["n"] < min_support,
        }
    return result


def misclassified(frame, y_pred: np.ndarray, proba: np.ndarray, labels: list[str], model: str):
    """Rows for misclassified.csv (frame = the test rows, same order as y_pred)."""
    rows = []
    for row, predicted, probabilities in zip(
        frame.itertuples(index=False), y_pred, proba, strict=True
    ):
        if int(predicted) != int(row.y):
            rows.append(
                {
                    "model": model,
                    "sample_id": row.sample_id,
                    "language": row.language,
                    "true": labels[int(row.y)],
                    "predicted": labels[int(predicted)],
                    "top_probability": round(float(probabilities.max()), 4),
                    "true_probability": round(float(probabilities[int(row.y)]), 4),
                }
            )
    return rows


def plot_confusion_matrix(matrix: list[list[int]], labels: list[str], title: str, path: Path):
    """Counts (left) and row-normalized shares (right) - row = true class."""
    counts = np.asarray(matrix, dtype=float)
    shares = counts / np.maximum(counts.sum(axis=1, keepdims=True), 1)
    figure = Figure(figsize=(11, 4.6), layout="constrained")
    for axis, values, name, fmt in zip(
        figure.subplots(1, 2),
        (counts, shares),
        ("counts", "row-normalized"),
        ("{:.0f}", "{:.2f}"),
        strict=True,
    ):
        image = axis.imshow(values, cmap="Blues", vmin=0, vmax=values.max() or 1)
        axis.set_xticks(range(len(labels)), labels, rotation=30, ha="right")
        axis.set_yticks(range(len(labels)), labels)
        axis.set_xlabel("predicted")
        axis.set_ylabel("true")
        axis.set_title(name)
        limit = (values.max() or 1) / 2
        for i in range(len(labels)):
            for j in range(len(labels)):
                axis.text(
                    j,
                    i,
                    fmt.format(values[i, j]),
                    ha="center",
                    va="center",
                    color="white" if values[i, j] > limit else "black",
                )
        figure.colorbar(image, ax=axis, shrink=0.8)
    figure.suptitle(title)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=130)
    return path


def confusion_text(matrix: list[list[int]], labels: list[str]) -> str:
    """The confusion matrix as a plain-text table (rows = true, columns = predicted)."""
    width = max(len(label) for label in labels) + 2
    head = "true \\ predicted".ljust(width + 4) + "".join(label.rjust(width) for label in labels)
    lines = [head]
    for label, row in zip(labels, matrix, strict=True):
        lines.append(label.ljust(width + 4) + "".join(str(v).rjust(width) for v in row))
    return "\n".join(lines)
