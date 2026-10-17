"""Calibrate the verdict tiers on the 9A out-of-fold predictions, per subset of arms.

Part 9: Batch B-1 - end-to-end URL analysis engine.

How the thresholds are chosen (viva):

1. The OOF fused probabilities of train+val are rebuilt EXACTLY as Part 9A built them:
   the final strategy is fitted on 4 folds of the stored arm OOF probabilities and
   predicts the 5th (``strategies.cross_validate`` logic). For the full arm set this
   reproduces 9A's threshold (checked, ``reproduces_9a``).
2. For every non-empty subset of arms (an arm off or failing), each fold model is
   applied with its late-fusion weights RENORMALIZED over the subset - the same
   renormalization the live API applies - giving that subset's OOF probabilities.
3. Malicious cut-off t_m = Part 9A's rule (``operating_point.choose_threshold``): the
   LARGEST P(benign) cut-off whose OOF benign FPR is <= 2 %.
   Suspicious cut-off t_s = the SMALLEST cut-off at which >= 95 % of the OOF threat
   pages fall below it (threat recall target), never below t_m.
4. The test pages are never used here (reported once in reports/verdict/).

Weighted / mean fusion is linear, so a subset is exactly "the same model without that
arm". Stacking / hybrid are not: for a subset they fall back to the plain mean of the
remaining arms (stated in the response warnings).
"""

from __future__ import annotations

import hashlib
import itertools
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from c2_analyzer.config import resolve_path
from c2_analyzer.fusion.common import ARM_ORDER, FusionConfig
from c2_analyzer.fusion.operating_point import choose_threshold
from c2_analyzer.fusion.strategies import FusionInputs, make_strategy
from c2_analyzer.fusion.verdict import GENERATED_MARKER, subset_key

LINEAR = ("mean", "weighted")


# ---- fusing a subset of arms (shared with the live orchestrator) ---------------------------


def subset_weights(model, arms) -> dict[str, float]:
    """The model's late-fusion weights renormalized over ``arms`` (linear strategies).

    Non-linear strategies (and a subset whose weights are all 0) -> equal weights."""
    chosen = [arm for arm in model.arms if arm in set(arms)]
    if not chosen:
        return {}
    if model.name in LINEAR:
        raw = model.weights()
        total = sum(raw[arm] for arm in chosen)
        if total > 0:
            return {arm: raw[arm] / total for arm in chosen}
    return {arm: 1 / len(chosen) for arm in chosen}


def is_exact(model, arms) -> bool:
    """True if fusing ``arms`` is exactly the trained model (no fallback)."""
    return model.name in LINEAR or set(arms) == set(model.arms)


def fuse_arms(model, inputs: FusionInputs, arms) -> np.ndarray:
    """(n, k) fused probabilities of ``arms`` (a subset of the model's arms)."""
    if set(arms) == set(model.arms) and model.name not in LINEAR:
        return model.predict_proba(inputs)
    weights = subset_weights(model, arms)
    if not weights:
        raise ValueError("no arm to fuse")
    fused = sum(w * np.asarray(inputs.probs[arm], dtype=float) for arm, w in weights.items())
    return fused / fused.sum(axis=1, keepdims=True)  # guard against float drift


def fusion_fingerprint(bundle: dict[str, Any]) -> str:
    """Changes whenever the saved fusion model changes (thresholds must follow)."""
    keys = ("strategy", "arms", "labels", "params", "split_fingerprint", "trained_at")
    text = json.dumps({key: bundle.get(key) for key in keys}, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def subsets(arms: list[str]) -> list[list[str]]:
    """Every non-empty subset, in ARM_ORDER, largest first."""
    ordered = [arm for arm in ARM_ORDER if arm in arms]
    out = []
    for size in range(len(ordered), 0, -1):
        out.extend(list(combo) for combo in itertools.combinations(ordered, size))
    return out


# ---- thresholds --------------------------------------------------------------------------


def recall_threshold(y: np.ndarray, proba: np.ndarray, benign: int, target: float) -> float:
    """Smallest cut-off t with share(threat pages with P(benign) < t) >= target."""
    scores = np.sort(np.asarray(proba, dtype=float)[np.asarray(y) != benign, benign])
    if not len(scores):
        raise ValueError("no threat page to set the threshold on")
    needed = int(np.ceil(target * len(scores) - 1e-9))
    needed = min(max(needed, 1), len(scores))
    return float(np.nextafter(scores[needed - 1], np.inf))


def tier_stats(y, proba, benign: int, malicious: float, suspicious: float) -> dict:
    """OOF benign FPR and threat recall of both tiers."""
    p = np.asarray(proba, dtype=float)[:, benign]
    y = np.asarray(y)
    is_benign = y == benign
    flagged_m, flagged_s = p < malicious, p < suspicious
    return {
        "n_pages": int(len(y)),
        "n_benign": int(is_benign.sum()),
        "benign_fpr_malicious": float(flagged_m[is_benign].mean()),
        "benign_fpr_flagged": float(flagged_s[is_benign].mean()),
        "threat_recall_malicious": float(flagged_m[~is_benign].mean()),
        "threat_recall_flagged": float(flagged_s[~is_benign].mean()),
    }


def fold_models(data, bundle: dict, config: FusionConfig) -> tuple[dict[int, Any], FusionInputs]:
    """The 9A fusion strategy fitted on every 4-fold training set (fold -> model)."""
    arms = list(bundle["arms"])
    inputs = data.inputs(arms, data.ids("pool"))
    y, folds = data.y("pool"), data.folds()
    models = {}
    for fold in sorted(np.unique(folds).tolist()):
        held = folds == fold
        model = make_strategy(bundle["strategy"], config, config.seed)
        models[fold] = model.fit(inputs.take(~held), y[~held], folds[~held])
    return models, inputs


def oof_for_subset(models: dict[int, Any], inputs: FusionInputs, folds, arms) -> np.ndarray:
    fused = np.zeros((inputs.n, len(inputs.labels)))
    for fold, model in models.items():
        held = np.asarray(folds) == fold
        fused[held] = fuse_arms(model, inputs.take(held), arms)
    return fused


def calibrate(version: str, policy_tiers: dict, log=print) -> dict:
    """Thresholds for every arm subset + diagnostics (nothing written)."""
    from c2_analyzer.fusion.data import FusionData
    from c2_analyzer.fusion.model import load_bundle

    config = FusionConfig.load()
    bundle = load_bundle(config.models_dir(version))
    if bundle is None:
        raise FileNotFoundError(f"no fusion model for {version} - run scripts/run_ablation.py")
    data = FusionData.load(version, config)
    if bundle["split_fingerprint"] != data.ref.split_fingerprint:
        raise ValueError("the fusion model was trained on another split - re-run run_ablation.py")
    missing = [arm for arm in bundle["arms"] if arm not in data.oofs]
    if missing:
        raise ValueError(f"no OOF table for {', '.join(missing)}")
    labels = data.labels
    benign = labels.index("benign")
    fpr_target = float(policy_tiers["malicious_benign_fpr_target"])
    recall_target = float(policy_tiers["suspicious_threat_recall_target"])
    y, folds = data.y("pool"), data.folds()
    log(f"fitting {bundle['strategy']} on the 5 CV training sets ...")
    models, inputs = fold_models(data, bundle, config)

    thresholds: dict[str, dict] = {}
    full_key = subset_key(bundle["arms"])
    for arms in subsets(list(bundle["arms"])):
        key = subset_key(arms)
        oof = oof_for_subset(models, inputs, folds, arms)
        malicious = float(choose_threshold(y, oof, benign, fpr_target)["threshold"])
        suspicious = max(malicious, recall_threshold(y, oof, benign, recall_target))
        stats = tier_stats(y, oof, benign, malicious, suspicious)
        thresholds[key] = {
            "malicious_below_p_benign": malicious,
            "suspicious_below_p_benign": suspicious,
            "exact_model": bool(is_exact(models[next(iter(models))], arms)),
            "oof": {k: round(v, 4) if isinstance(v, float) else v for k, v in stats.items()},
        }
        log(
            f"  {key:<38} malicious P(benign) < {malicious:.4f}  suspicious < {suspicious:.4f}"
            f"  OOF FPR {stats['benign_fpr_malicious']:.1%}/{stats['benign_fpr_flagged']:.1%}"
            f"  recall {stats['threat_recall_malicious']:.1%}/{stats['threat_recall_flagged']:.1%}"
        )
    stored = float(bundle.get("threshold", {}).get("threshold", float("nan")))
    reproduces = abs(thresholds[full_key]["malicious_below_p_benign"] - stored) < 1e-9
    calibration = {
        "dataset_version": version,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "fusion_strategy": bundle["strategy"],
        "fusion_arms": list(bundle["arms"]),
        "fusion_weights": {k: float(v) for k, v in (bundle.get("weights") or {}).items()},
        "fusion_fingerprint": fusion_fingerprint(bundle),
        "split_fingerprint": bundle["split_fingerprint"],
        "oof_pages": int(len(y)),
        "reproduces_9a_threshold": bool(reproduces),
        "part_9a_threshold": stored,
        "rule": "Malicious if P(benign) < malicious_below_p_benign (largest cut-off with OOF "
        f"benign FPR <= {fpr_target:.0%}); Suspicious if P(benign) < suspicious_below_p_benign "
        f"(smallest cut-off with OOF threat recall >= {recall_target:.0%}); else Legitimate",
    }
    if not reproduces:
        log(f"WARNING: full-arm threshold differs from Part 9A's stored {stored}")
    return {"calibration": calibration, "thresholds": thresholds}


def write_verdict_config(result: dict, path: Path | None = None) -> Path:
    """Replace everything below the GENERATED marker of configs/verdict.yaml."""
    path = path or resolve_path(Path("configs")) / "verdict.yaml"
    text = path.read_text(encoding="utf-8")
    if GENERATED_MARKER not in text:
        raise ValueError(f"{path} has no generated-section marker")
    head = text.split(GENERATED_MARKER)[0]
    body = yaml.safe_dump(result, sort_keys=False, allow_unicode=True, width=100)
    path.write_text(f"{head}{GENERATED_MARKER}\n{body}", encoding="utf-8")
    return path
