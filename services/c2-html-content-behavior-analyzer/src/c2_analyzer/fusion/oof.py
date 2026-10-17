"""Out-of-fold (OOF) class probabilities of every arm - the input of the fusion models.

Part 9: Tri-modal fusion + ablation study (Batch A, task 1).

Why stacking needs OOF predictions (viva):
    A fusion model learns HOW MUCH to trust each arm from the arms' probabilities. If those
    probabilities came from an arm model that was trained on the same page, they would be
    over-confident (a Random Forest is ~100 % sure about pages it has memorised), and the
    fusion model would learn to trust that arm far too much - then fail on new pages,
    where the arm is much less sure. So for every train+val page we use the probability
    from a model that NEVER saw that page: the shared grouped 5-fold CV
    (data/splits/<v>/cv_folds.csv) trains each arm on 4 folds and predicts the 5th. The
    folds are grouped by cluster_id, so a near-duplicate of the page was not in training
    either (checked here: a cluster in two folds is refused). These are the "out-of-fold"
    (OOF) predictions; the fusion model is trained and cross-validated on them only.
    Test pages get the probabilities of the arm's FINAL model (trained on train+val) -
    exactly what a new page gets in production. The test split never takes part in any
    choice; it is scored once at the end (ablation.py).

Each arm reuses its own Part's training code and the hyperparameters that Part chose by
CV (nothing is re-tuned here, nothing is copied):
    dom         Part 4  best model by CV (classifiers/dom_baseline: prepare_dataset,
                        cross_validate with the bundle's params; test = the saved bundle)
    behavior    Part 8  same protocol, js + behavior features (behavior/baseline.py)
    text_tfidf  Part 6A TF-IDF + LogReg with the saved C (text_baseline.cv_probabilities)
    text_xlmr   Part 6A XLM-R - OPTIONAL: its fold models need a GPU, so they are trained on
                        Colab (train_xlmr.py export-bundle --cv / import-oof); test = the
                        Part 6A final model.
For the tabular arms the recomputed OOF is also compared with the OOF stored in the Part
4 / 8 bundle (same folds, same seed -> must match; recorded in the manifest).

Outputs: ``data/processed/fusion/<v>/oof_<arm>.csv`` (sample_id, split, fold, p_<class>...;
fold = -1 for test) + ``oof_<arm>.json`` (model, params, versions, fingerprints).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

from c2_analyzer.classifiers.dom_baseline.common import (
    BaselineConfig,
    FeatureSource,
    library_versions,
    load_bundles,
)
from c2_analyzer.classifiers.dom_baseline.data import label_order, prepare_dataset
from c2_analyzer.classifiers.dom_baseline.predict import best_model
from c2_analyzer.classifiers.dom_baseline.report import check_bundles
from c2_analyzer.classifiers.dom_baseline.train import _proba, cross_validate
from c2_analyzer.dataset.manifest import manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.splits import EXCLUDED, load_cv_folds, load_split, split_fingerprint
from c2_analyzer.fusion.common import ID_COLUMNS, FusionConfig, prob_columns
from c2_analyzer.utils.io import atomic_write_csv, write_json

SUM_TOLERANCE = 1e-3  # stored probabilities are rounded to 6 decimals


class OofError(ValueError):
    """An OOF file does not belong to the current split / folds / classes."""


# ---- the reference: which pages, which fold, which classes --------------------------------


def folds_fingerprint(folds: pd.DataFrame) -> str:
    """sha256 of the sorted (sample_id, fold) pairs of cv_folds.csv."""
    lines = sorted(f"{row.sample_id},{int(row.fold)}" for row in folds.itertuples(index=False))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


@dataclass
class Reference:
    """The shared split of a version as the fusion sees it."""

    version: str
    labels: list[str]
    frame: pd.DataFrame  # sample_id, label, y, split, fold (-1 = test), cluster_id
    split_fingerprint: str
    folds_fingerprint: str
    excluded_classes: dict = field(default_factory=dict)

    @property
    def pool(self) -> pd.DataFrame:
        return self.frame[self.frame["split"].isin(["train", "val"])]

    @property
    def test(self) -> pd.DataFrame:
        return self.frame[self.frame["split"] == "test"]


def load_reference(version: str, splits_root: Path | None = None) -> Reference:
    split, info = load_split(version, splits_root)
    fingerprint = split_fingerprint(split)
    if info.get("split_fingerprint") and info["split_fingerprint"] != fingerprint:
        raise OofError(f"split.csv of {version} no longer matches split.json - re-run the split")
    included = split[split["split"] != EXCLUDED].copy()
    labels = label_order(info.get("included_classes") or sorted(included["label"].unique()))
    index = {name: i for i, name in enumerate(labels)}
    included["y"] = included["label"].map(index).astype(int)
    folds = load_cv_folds(version, splits_root)
    fold_of = folds.set_index("sample_id")["fold"]
    included["fold"] = included["sample_id"].map(fold_of).fillna(-1).astype(int)
    pool = included["split"].isin(["train", "val"])
    if (included.loc[pool, "fold"] < 0).any() or (included.loc[~pool, "fold"] >= 0).any():
        raise OofError("cv_folds.csv does not match split.csv (re-run the split)")
    spread = included.loc[pool].groupby("cluster_id")["fold"].nunique()
    if (spread > 1).any():
        raise OofError(
            f"clusters in several CV folds (e.g. {spread[spread > 1].index[:3].tolist()}) - "
            "OOF predictions would not be out-of-cluster; re-run the split"
        )
    frame = included[["sample_id", "label", "y", "split", "fold", "cluster_id"]]
    return Reference(
        version=version,
        labels=labels,
        frame=frame.reset_index(drop=True),
        split_fingerprint=fingerprint,
        folds_fingerprint=folds_fingerprint(folds),
        excluded_classes=dict(info.get("excluded_classes") or {}),
    )


# ---- one arm's OOF table -------------------------------------------------------------------


@dataclass
class ArmOof:
    """Probabilities of one arm for every included page (OOF for train+val, final for test)."""

    arm: str
    labels: list[str]
    frame: pd.DataFrame  # ID_COLUMNS + p_<class>
    manifest: dict = field(default_factory=dict)

    def proba(self, sample_ids) -> np.ndarray:
        indexed = self.frame.set_index("sample_id")
        return indexed.loc[list(sample_ids), prob_columns(self.labels)].to_numpy(dtype=float)


def make_frame(
    ref: Reference, pool_ids, pool_proba: np.ndarray, test_ids, test_proba: np.ndarray
) -> pd.DataFrame:
    """OOF table in the reference's row order (pool ids + test ids must cover it exactly)."""
    columns = prob_columns(ref.labels)
    parts = pd.concat(
        [
            pd.DataFrame(np.asarray(pool_proba, dtype=float), columns=columns).assign(
                sample_id=list(pool_ids)
            ),
            pd.DataFrame(np.asarray(test_proba, dtype=float), columns=columns).assign(
                sample_id=list(test_ids)
            ),
        ],
        ignore_index=True,
    )
    if parts["sample_id"].duplicated().any():
        raise OofError("a page has two predictions")
    merged = ref.frame[["sample_id", "split", "fold"]].merge(parts, on="sample_id", how="left")
    if merged[columns].isna().to_numpy().any():
        missing = merged.loc[merged[columns].isna().any(axis=1), "sample_id"].tolist()
        raise OofError(f"no prediction for {len(missing)} page(s), e.g. {missing[:3]}")
    if len(parts) != len(merged):
        raise OofError("predictions for pages that are not in the split")
    merged[columns] = merged[columns].round(6)
    return merged[ID_COLUMNS + columns]


def check_frame(frame: pd.DataFrame, ref: Reference) -> list[str]:
    """Problems of an OOF table vs the current split (empty = OK)."""
    columns = prob_columns(ref.labels)
    if list(frame.columns) != ID_COLUMNS + columns:
        return [f"columns {list(frame.columns)} != {ID_COLUMNS + columns}"]
    problems = []
    expected = ref.frame.set_index("sample_id")
    got = frame.set_index("sample_id")
    if set(got.index) != set(expected.index) or got.index.duplicated().any():
        extra = sorted(set(got.index) - set(expected.index))[:3]
        missing = sorted(set(expected.index) - set(got.index))[:3]
        problems.append(f"sample ids differ from the split (extra {extra}, missing {missing})")
        return problems
    got = got.loc[expected.index]
    if (got["split"] != expected["split"]).any():
        problems.append("split column differs from split.csv")
    if (got["fold"].astype(int) != expected["fold"]).any():
        problems.append("fold column differs from cv_folds.csv")
    values = got[columns].to_numpy(dtype=float)
    if not np.isfinite(values).all() or (values < 0).any():
        problems.append("probabilities must be finite and >= 0")
    elif np.abs(values.sum(axis=1) - 1).max() > SUM_TOLERANCE:
        problems.append("probabilities of a page do not sum to 1")
    return problems


def oof_paths(folder: Path, arm: str) -> tuple[Path, Path]:
    return Path(folder) / f"oof_{arm}.csv", Path(folder) / f"oof_{arm}.json"


def write_oof(oof: ArmOof, folder: Path) -> tuple[Path, Path]:
    csv_path, json_path = oof_paths(folder, oof.arm)
    atomic_write_csv(oof.frame, csv_path, list(oof.frame.columns))
    write_json(oof.manifest, json_path)
    return csv_path, json_path


def load_oof(arm: str, ref: Reference, folder: Path) -> ArmOof | None:
    """The stored OOF of ``arm`` (None if there is none); OofError if it is stale."""
    csv_path, json_path = oof_paths(folder, arm)
    if not csv_path.is_file() or not json_path.is_file():
        return None
    manifest = json.loads(json_path.read_text(encoding="utf-8"))
    problems = []
    if manifest.get("split_fingerprint") != ref.split_fingerprint:
        problems.append("made on another split")
    if manifest.get("cv_folds_fingerprint") != ref.folds_fingerprint:
        problems.append("made with other CV folds")
    if manifest.get("classes") != ref.labels:
        problems.append(f"classes {manifest.get('classes')} != {ref.labels}")
    frame = pd.read_csv(csv_path, dtype={"sample_id": str, "split": str})
    problems += check_frame(frame, ref) if not problems else []
    if problems:
        raise OofError(f"{csv_path.name} is stale: {'; '.join(problems)}")
    return ArmOof(arm=arm, labels=ref.labels, frame=frame, manifest=manifest)


def base_manifest(arm: str, ref: Reference, config: FusionConfig) -> dict:
    return {
        "arm": arm,
        "display": config.arm_display(arm),
        "dataset_version": ref.version,
        "classes": ref.labels,
        "split_fingerprint": ref.split_fingerprint,
        "cv_folds_fingerprint": ref.folds_fingerprint,
        "n_oof": int(len(ref.pool)),
        "n_test": int(len(ref.test)),
        "oof_rule": "train+val: model trained on the OTHER grouped CV folds; "
        "test: the arm's final model (trained on train+val)",
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


# ---- arm builders ----------------------------------------------------------------------------


def tabular_oof(
    arm: str,
    source: FeatureSource,
    ref: Reference,
    config: FusionConfig,
    log=print,
    baseline: BaselineConfig | None = None,
    dataset=None,
    bundles: dict | None = None,
) -> ArmOof:
    """Part 4 / Part 8 arm: the best model by CV, its params, Part 4's cross_validate.

    ``baseline`` / ``dataset`` / ``bundles`` default to the Part's own files (tests pass toys).
    """
    baseline = baseline or BaselineConfig.load(source)
    dataset = dataset or prepare_dataset(
        ref.version,
        baseline.correlation_threshold,
        manifests=manifests_dir(MetadataStore()),
        source=source,
    )
    if dataset.labels != ref.labels:
        raise OofError(f"{arm}: classes {dataset.labels} != {ref.labels}")
    bundles = bundles if bundles is not None else load_bundles(baseline, ref.version)
    if not bundles:
        raise FileNotFoundError(
            f"no trained {arm} models for {ref.version} - run: python "
            f"{source.all_hint(ref.version)}"
        )
    check_bundles(bundles, dataset, source)  # same split, features, classes, dictionary
    name = best_model(bundles)
    bundle = bundles[name]
    log(f"{arm}: {bundle['display_name']} (best by CV) - 5 fold models ...")
    _, _, oof = cross_validate(name, bundle["params"], dataset, baseline)
    pool, test = dataset.rows("train", "val"), dataset.rows("test")
    test_proba = _proba(bundle["estimator"], dataset.X("test"), len(dataset.labels))
    stored = bundle["cv"].get("out_of_fold", {})
    stored_diff = None
    if stored.get("sample_id") == pool["sample_id"].tolist():
        stored_diff = float(np.abs(np.asarray(stored["probabilities"]) - oof).max())
    frame = make_frame(ref, pool["sample_id"], oof, test["sample_id"], test_proba)
    manifest = {
        **base_manifest(arm, ref, config),
        "part": "Part 4" if arm == "dom" else "Part 8",
        "model": name,
        "model_display": bundle["display_name"],
        "params": bundle["params"],
        "selection": "best mean CV macro-F1 of the Part's models (never test)",
        "features_used": len(bundle["features"]),
        "feature_set_version": bundle["feature_set_version"],
        "dictionary_hash": bundle["dictionary_hash"],
        "model_trained_at": bundle["trained_at"],
        "part_cv_macro_f1": bundle["cv"]["mean"]["macro_f1"],
        "max_abs_diff_vs_part_oof": stored_diff,
        "reproduces_part_oof": None if stored_diff is None else stored_diff < 1e-5,
        "library_versions": library_versions(),
    }
    return ArmOof(arm=arm, labels=ref.labels, frame=frame, manifest=manifest)


def tfidf_oof(ref: Reference, config: FusionConfig, log=print) -> ArmOof:
    """Part 6A TF-IDF arm: the saved C, Part 6A's cv_probabilities on the shared folds."""
    from c2_analyzer.nlp.common import BASELINE_NAME, XlmrConfig
    from c2_analyzer.nlp.dataset import build_examples
    from c2_analyzer.nlp.text_baseline import cv_probabilities, predict_proba

    xlmr = XlmrConfig.load()
    data = build_examples(ref.version)
    path = xlmr.baseline_models_dir(ref.version) / f"{BASELINE_NAME}.joblib"
    if not path.is_file():
        raise FileNotFoundError(
            f"no TF-IDF baseline for {ref.version} - run: python scripts/train_xlmr.py "
            f"baseline --version {ref.version}"
        )
    bundle = joblib.load(path)  # written by this project's text_baseline.py only
    problems = []
    if bundle["split_fingerprint"] != ref.split_fingerprint:
        problems.append("another split")
    if bundle["text_rules_hash"] != data.meta["text_rules_hash"]:
        problems.append("other Part 5A text rules")
    if list(bundle["labels"]) != ref.labels:
        problems.append("other classes")
    settings = xlmr.baseline
    fixed = {key: value for key, value in bundle["params"].items() if key != "C"}
    if any(settings.get(key) != value for key, value in fixed.items()):
        problems.append("other text_baseline settings in configs/xlmr.yaml")
    if problems:
        raise OofError(
            f"text_tfidf model is stale ({', '.join(problems)}) - run: python "
            f"scripts/train_xlmr.py baseline --version {ref.version}"
        )
    pool, test = data.rows("train", "val"), data.rows("test")
    fold_of = ref.frame.set_index("sample_id")["fold"]
    folds = np.array([int(fold_of[row["sample_id"]]) for row in pool])
    y = np.array([row["label_id"] for row in pool])
    log(f"text_tfidf: TF-IDF + LogReg (C={bundle['params']['C']:g}) - 5 fold models ...")
    oof = cv_probabilities(
        [row["text"] for row in pool], y, folds, settings, bundle["params"]["C"], len(ref.labels)
    )
    test_proba = predict_proba(bundle["pipeline"], [row["text"] for row in test], len(ref.labels))
    frame = make_frame(
        ref, [row["sample_id"] for row in pool], oof, [row["sample_id"] for row in test], test_proba
    )
    recomputed = float(
        np.mean(
            [
                f1_score(
                    y[folds == k],
                    oof[folds == k].argmax(axis=1),
                    labels=list(range(len(ref.labels))),
                    average="macro",
                    zero_division=0,
                )
                for k in sorted(set(folds.tolist()))
            ]
        )
    )
    results_path = xlmr.baseline_reports_dir(ref.version) / "results.json"
    part_cv = None
    if results_path.is_file():
        results = json.loads(results_path.read_text(encoding="utf-8"))
        part_cv = results["models"][BASELINE_NAME]["cv"]["mean"]["macro_f1"]
    manifest = {
        **base_manifest("text_tfidf", ref, config),
        "part_cv_macro_f1": part_cv,
        "recomputed_cv_macro_f1": recomputed,
        "reproduces_part_oof": None if part_cv is None else abs(part_cv - recomputed) < 1e-9,
        "part": "Part 6A",
        "model": BASELINE_NAME,
        "model_display": "TF-IDF char 2-5 + LogReg",
        "params": bundle["params"],
        "selection": "C by mean CV macro-F1 over the shared folds (never test)",
        "text_rules_hash": data.meta["text_rules_hash"],
        "model_trained_at": bundle["trained_at"],
        "library_versions": library_versions(),
    }
    return ArmOof(arm="text_tfidf", labels=ref.labels, frame=frame, manifest=manifest)


def build_oof(
    version: str,
    arms: list[str] | None = None,
    config: FusionConfig | None = None,
    log=print,
) -> dict[str, ArmOof]:
    """Compute + write the OOF tables of the locally trainable arms (dom, behavior, tfidf)."""
    from c2_analyzer.behavior.baseline import BEHAVIOR_SOURCE
    from c2_analyzer.classifiers.dom_baseline.sources import DOM_SOURCE

    config = config or FusionConfig.load()
    ref = load_reference(version)
    folder = config.oof_dir(version)
    builders = {
        "dom": lambda: tabular_oof("dom", DOM_SOURCE, ref, config, log),
        "behavior": lambda: tabular_oof("behavior", BEHAVIOR_SOURCE, ref, config, log),
        "text_tfidf": lambda: tfidf_oof(ref, config, log),
    }
    built = {}
    for arm in arms or list(builders):
        if arm not in builders:
            raise ValueError(f"{arm} OOF cannot be built locally (text_xlmr: use import-oof)")
        built[arm] = builders[arm]()
        write_oof(built[arm], folder)
    return built


def load_all(
    ref: Reference, config: FusionConfig, folder: Path | None = None
) -> tuple[dict[str, ArmOof], list[str]]:
    """(available arms, missing arm names) from data/processed/fusion/<v>/."""
    folder = folder or config.oof_dir(ref.version)
    available, missing = {}, []
    for arm in config.arms:
        oof = load_oof(arm, ref, folder)
        if oof is None:
            missing.append(arm)
        else:
            available[arm] = oof
    return available, missing
