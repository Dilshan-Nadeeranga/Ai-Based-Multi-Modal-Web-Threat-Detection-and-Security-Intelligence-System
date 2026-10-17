"""Synthetic data for the Part 9A fusion tests (shared by test_fusion.py / test_inspector.py).

No real dataset, no trained arm: a toy split with cluster-pure folds, arm probabilities
that carry a known amount of label signal, and random tabular features.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import numpy as np
import pandas as pd

from c2_analyzer.dataset.splits import split_fingerprint
from c2_analyzer.fusion.common import FusionConfig, prob_columns
from c2_analyzer.fusion.data import FusionData
from c2_analyzer.fusion.oof import ArmOof, Reference, folds_fingerprint, make_frame

LABELS = ["benign", "phishing", "malware_delivery"]


def toy_rows(n_pool: int = 60, n_test: int = 24, labels=LABELS) -> list[dict]:
    """Pages with a label cycle; pool pages get fold i % 5, clusters never span folds."""
    rows = []
    for i in range(n_pool + n_test):
        label = labels[i % len(labels)]
        pool = i < n_pool
        rows.append(
            {
                "sample_id": f"c2_{label}_{i:06d}",
                "label": label,
                "language": "en",
                "cluster_id": f"cl_{i // 2:06d}" if pool else f"cl_{500000 + i:06d}",
                "split": ("train" if i % 4 else "val") if pool else "test",
                "fold": (i // 2) % 5 if pool else -1,  # both pages of a cluster share a fold
            }
        )
    return rows


def write_split(root: Path, version: str, rows: list[dict], labels=LABELS) -> Path:
    """data/splits/<version>/{split.csv, split.json, cv_folds.csv} like Part 4 writes them."""
    folder = Path(root) / version
    folder.mkdir(parents=True, exist_ok=True)
    split = pd.DataFrame(rows)[["sample_id", "label", "language", "cluster_id", "split"]]
    split.to_csv(folder / "split.csv", index=False)
    folds = pd.DataFrame([r for r in rows if r["split"] != "test"])[
        ["sample_id", "label", "cluster_id", "fold"]
    ]
    folds.to_csv(folder / "cv_folds.csv", index=False)
    info = {
        "version": version,
        "split_fingerprint": split_fingerprint(split),
        "included_classes": list(labels),
        "excluded_classes": {},
        "manifest": {"fingerprint": "toy"},
    }
    (folder / "split.json").write_text(json.dumps(info), encoding="utf-8")
    return Path(root)


def toy_reference(rows: list[dict] | None = None, labels=LABELS) -> Reference:
    rows = rows or toy_rows(labels=labels)
    frame = pd.DataFrame(rows)
    frame["y"] = frame["label"].map({name: i for i, name in enumerate(labels)}).astype(int)
    folds = frame.loc[frame["split"] != "test", ["sample_id", "fold"]]
    return Reference(
        version="v9.1",
        labels=list(labels),
        frame=frame[["sample_id", "label", "y", "split", "fold", "cluster_id"]],
        split_fingerprint=split_fingerprint(frame),
        folds_fingerprint=folds_fingerprint(folds),
    )


def signal_proba(y: np.ndarray, k: int, quality: float, seed: int) -> np.ndarray:
    """Probabilities that put ``quality`` extra mass on the true class (+ Dirichlet noise)."""
    rng = np.random.default_rng(seed)
    noise = rng.dirichlet(np.ones(k), size=len(y))
    proba = (1 - quality) * noise
    proba[np.arange(len(y)), y] += quality
    return proba / proba.sum(axis=1, keepdims=True)


def toy_oof(ref: Reference, arm: str, quality: float, seed: int) -> ArmOof:
    k = len(ref.labels)
    pool, test = ref.pool, ref.test
    frame = make_frame(
        ref,
        pool["sample_id"],
        signal_proba(pool["y"].to_numpy(), k, quality, seed),
        test["sample_id"],
        signal_proba(test["y"].to_numpy(), k, quality, seed + 100),
    )
    manifest = {
        "arm": arm,
        "display": arm,
        "classes": ref.labels,
        "split_fingerprint": ref.split_fingerprint,
        "cv_folds_fingerprint": ref.folds_fingerprint,
    }
    return ArmOof(arm=arm, labels=ref.labels, frame=frame, manifest=manifest)


def fast_config() -> FusionConfig:
    """configs/fusion.yaml with a small bootstrap and a small XGBoost (fast tests)."""
    base = FusionConfig.load()
    raw = copy.deepcopy(base.raw)
    raw["bootstrap"]["n_resamples"] = 50
    raw["strategies"]["hybrid"]["params"]["n_estimators"] = 20
    return FusionConfig(raw=raw, seed=base.seed)


def toy_features(ref: Reference, arm: str, n: int = 6, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    values = rng.normal(size=(len(ref.frame), n))
    values[:, 0] += ref.frame["y"].to_numpy()  # one informative feature
    values[:, -1] = 1.0  # one constant feature (the hybrid must drop it)
    frame = pd.DataFrame(values, columns=[f"{arm}.f{i}" for i in range(n)])
    frame.index = ref.frame["sample_id"].to_numpy()
    return frame


def toy_data(arms=("dom", "behavior", "text_tfidf"), config: FusionConfig | None = None):
    config = config or fast_config()
    ref = toy_reference()
    quality = {"dom": 0.5, "behavior": 0.3, "text_tfidf": 0.45, "text_xlmr": 0.4}
    oofs = {arm: toy_oof(ref, arm, quality[arm], seed=i) for i, arm in enumerate(arms)}
    features = {
        arm: toy_features(ref, arm, seed=i) for i, arm in enumerate(arms) if not config.is_text(arm)
    }
    missing = [arm for arm in config.arms if arm not in arms]
    return FusionData(ref, oofs, missing, config, features, languages={})


def columns(labels=LABELS) -> list[str]:
    return ["sample_id", "split", "fold"] + prob_columns(labels)
