"""Benign-FPR operating point: a threshold on P(benign) so that <= 2 % of benign pages are flagged.

Part 9: Tri-modal fusion + ablation study (Batch A, task 3).

Why (viva): the proposal requires a benign false-positive rate of at most 2 % - a detector
that flags real banks and shops is switched off by its users. The argmax decision ("the
most probable class wins") has no such guarantee: every arm had 6-21 % benign FPR on test.
Rule used here:

    page is BENIGN  if P(benign) >= t
    otherwise       the most probable THREAT class

``t`` is chosen on the OUT-OF-FOLD fused probabilities of train+val (never on test) as the
LARGEST threshold whose OOF benign FPR is <= the target: larger t = more pages flagged =
more threats caught, so the largest allowed t costs the least recall. On the test pages
the threshold is applied once and both results are reported (argmax and FPR-constrained):
the FPR actually reached on test (with 34 benign test pages one page = 2.9 %, so "<= 2 %"
on test means 0 mistakes) and what it costs in threat recall and macro-F1.
"""

from __future__ import annotations

import numpy as np

from c2_analyzer.classifiers.dom_baseline.evaluate import benign_fpr, compute_metrics


def threshold_predict(proba: np.ndarray, benign: int, threshold: float) -> np.ndarray:
    """Benign if P(benign) >= threshold, else the most probable threat class."""
    proba = np.asarray(proba, dtype=float)
    threats = proba.copy()
    threats[:, benign] = -np.inf
    predicted = threats.argmax(axis=1)
    predicted[proba[:, benign] >= threshold] = benign
    return predicted


def choose_threshold(y: np.ndarray, proba: np.ndarray, benign: int, target: float) -> dict:
    """The largest t with benign FPR(t) <= target on these (OOF) pages.

    FPR(t) = share of benign pages with P(benign) < t; it only grows with t, so the answer
    is the (m+1)-th smallest benign P(benign) with m = floor(target * n_benign) pages
    allowed below it (ties stay benign because the rule uses >=).
    """
    y, proba = np.asarray(y, dtype=int), np.asarray(proba, dtype=float)
    scores = np.sort(proba[y == benign, benign])
    if not len(scores):
        raise ValueError("no benign page to set the threshold on")
    allowed = int(np.floor(target * len(scores) + 1e-9))
    threshold = 1.0 + 1e-9 if allowed >= len(scores) else float(scores[allowed])
    predicted = threshold_predict(proba, benign, threshold)
    return {
        "threshold": threshold,
        "target": target,
        "n_benign": int(len(scores)),
        "allowed_false_positives": allowed,
        "oof_benign_fpr": benign_fpr(y, predicted, benign),
        "oof_threat_recall": threat_recall(y, predicted, benign),
    }


def threat_recall(y: np.ndarray, predicted: np.ndarray, benign: int) -> float | None:
    """Share of threat pages flagged as ANY threat (detection rate; the class may differ)."""
    threat = np.asarray(y) != benign
    if not threat.any():
        return None
    return float((np.asarray(predicted)[threat] != benign).mean())


def evaluate_operating_point(
    y: np.ndarray, proba: np.ndarray, labels: list[str], benign: int, threshold: float
) -> dict:
    """Test metrics at argmax and at the threshold, side by side."""
    argmax = np.asarray(proba).argmax(axis=1)
    constrained = threshold_predict(proba, benign, threshold)
    at_argmax = compute_metrics(y, argmax, proba, labels)
    at_threshold = compute_metrics(y, constrained, proba, labels)
    return {
        "threshold": threshold,
        "argmax": {
            "benign_fpr": at_argmax["benign_fpr"],
            "macro_f1": at_argmax["macro_f1"],
            "threat_recall": threat_recall(y, argmax, benign),
            "per_class_recall": {k: v["recall"] for k, v in at_argmax["per_class"].items()},
        },
        "fpr_constrained": {
            "benign_fpr": at_threshold["benign_fpr"],
            "macro_f1": at_threshold["macro_f1"],
            "threat_recall": threat_recall(y, constrained, benign),
            "per_class_recall": {k: v["recall"] for k, v in at_threshold["per_class"].items()},
            "confusion_matrix": at_threshold["confusion_matrix"],
        },
        "predicted": constrained.tolist(),
    }
