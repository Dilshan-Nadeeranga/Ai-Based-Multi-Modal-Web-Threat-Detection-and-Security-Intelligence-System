"""Paired bootstrap confidence intervals for test macro-F1 (and differences between rows).

Part 9: Tri-modal fusion + ablation study (Batch A, task 4).

What the CI means (viva): the 68 test pages are one sample of the pages the detector will
meet. Drawing 68 pages WITH replacement from them, 1,000 times (seed 42), and recomputing
macro-F1 each time shows how much the score would move with another sample of the same
size; the middle 95 % of those values is the 95 % percentile CI. With 68 pages the CIs
are wide (about +/- 0.1), which is the honest message of a small test set.

"Paired": every row (arm or fusion model) is scored on the SAME 1,000 resamples, so the
difference "tri-modal minus best single arm" is computed per resample and gets its own
CI. If that CI includes 0, the test set cannot tell the two apart - the improvement may be
luck. (A CI that excludes 0 is evidence, not proof: 68 pages, several rows compared.)

Macro-F1 of a resample averages over the classes PRESENT in it (a resample without any of
the 4 crypto_scam pages cannot score crypto_scam; counting it as 0 would bias every row
down by the same accident).
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import f1_score


def resample_indices(n: int, n_resamples: int, seed: int) -> np.ndarray:
    """(n_resamples, n) page indices drawn with replacement - shared by all rows (paired)."""
    return np.random.default_rng(seed).integers(0, n, size=(n_resamples, n))


def macro_f1_present(y: np.ndarray, predicted: np.ndarray) -> float:
    present = sorted(set(np.asarray(y).tolist()))
    return float(f1_score(y, predicted, labels=present, average="macro", zero_division=0))


def bootstrap_scores(y: np.ndarray, predicted: np.ndarray, indices: np.ndarray) -> np.ndarray:
    y, predicted = np.asarray(y), np.asarray(predicted)
    return np.array([macro_f1_present(y[i], predicted[i]) for i in indices])


def interval(values: np.ndarray, confidence: float) -> tuple[float, float]:
    alpha = (1 - confidence) / 2
    low, high = np.quantile(values, [alpha, 1 - alpha])
    return float(low), float(high)


def summarize(point: float, scores: np.ndarray, confidence: float) -> dict:
    low, high = interval(scores, confidence)
    return {
        "point": float(point),
        "ci_low": low,
        "ci_high": high,
        "bootstrap_mean": float(scores.mean()),
        "bootstrap_std": float(scores.std()),
    }


def paired_difference(
    y: np.ndarray,
    predicted_a: np.ndarray,
    predicted_b: np.ndarray,
    indices: np.ndarray,
    confidence: float,
) -> dict:
    """CI of macro-F1(a) - macro-F1(b) over the same resamples."""
    a = bootstrap_scores(y, predicted_a, indices)
    b = bootstrap_scores(y, predicted_b, indices)
    difference = a - b
    point = macro_f1_present(y, predicted_a) - macro_f1_present(y, predicted_b)
    result = summarize(point, difference, confidence)
    result["includes_zero"] = bool(result["ci_low"] <= 0 <= result["ci_high"])
    result["share_a_better"] = float((difference > 0).mean())
    return result
