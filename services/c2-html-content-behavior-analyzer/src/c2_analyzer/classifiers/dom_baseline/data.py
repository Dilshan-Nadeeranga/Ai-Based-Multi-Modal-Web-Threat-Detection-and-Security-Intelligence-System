"""DOM feature dataset for the baseline: load, check, encode labels, clean features.

Part 4: DOM baseline classifier (tasks 1-2).

Inputs (both produced earlier, nothing is recomputed here):
    data/processed/dom_features/<version>/dom_features.csv + feature_dictionary.json   Part 3
    data/splits/<version>/split.csv + split.json + cv_folds.csv                   shared split

Why each check exists (viva):
- **Feature columns must equal the dictionary exactly** (same names, same
  order, same feature_set_version and dictionary hash as the code that will
  compute features at prediction time). Otherwise a model trained on one
  vector layout would silently be fed another one.
- **Labels are encoded in configs/labels.yaml order, restricted to the
  included classes** (v0.1: benign=0, phishing=1, malware_delivery=2). The
  numbers are contiguous because XGBoost requires 0..k-1; label_mapping.json
  records both these indices and the stable labels.yaml ids.
- **Feature cleaning is decided on the TRAIN split only.** Looking at
  val/test to decide which columns to keep would leak information about the
  evaluation data into the model design. Rules: drop features that are
  constant on train; for every pair with |Pearson r| > 0.98 on train, drop the
  one listed later in the dictionary (the earlier one is usually the simpler,
  more basic feature, e.g. node_count before element_count). Every drop is
  logged with its reason (dropped_features.csv).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from c2_analyzer.classifiers.dom_baseline.common import FeatureSource, default_source
from c2_analyzer.config import get_labels
from c2_analyzer.dataset.splits import EXCLUDED, check_current, load_cv_folds, load_split
from c2_analyzer.dom.dictionary import dictionary_hash, feature_names, load_dictionary
from c2_analyzer.dom.exporter import CSV_NAME, DICTIONARY_NAME, ID_COLUMNS
from c2_analyzer.dom.exporter import output_dir as features_output_dir


class DatasetError(ValueError):
    """The feature table and the split / dictionary do not fit together."""


@dataclass
class DomDataset:
    """The included pages of one version, ready for training."""

    version: str
    frame: pd.DataFrame  # ids, split, fold (train+val only, else -1), y, every dictionary feature
    all_features: list[str]  # the dictionary order (52 for dom_v1)
    features: list[str]  # after train-only cleaning (the model input, in dictionary order)
    labels: list[str]  # class index -> name
    dropped: list[dict] = field(default_factory=list)
    split_info: dict = field(default_factory=dict)
    feature_set_version: str = ""
    dictionary_hash: str = ""

    def rows(self, *splits: str) -> pd.DataFrame:
        return self.frame[self.frame["split"].isin(splits)]

    def X(self, *splits: str) -> np.ndarray:  # noqa: N802 - the usual ML name
        return self.rows(*splits)[self.features].to_numpy(dtype=float)

    def y(self, *splits: str) -> np.ndarray:
        return self.rows(*splits)["y"].to_numpy(dtype=int)

    @property
    def pilot(self) -> bool:
        return bool(self.split_info.get("excluded_classes"))


# ---- labels -------------------------------------------------------------------------------


def label_order(included: list[str]) -> list[str]:
    """Included classes in configs/labels.yaml order (unknown names are refused)."""
    known = get_labels()
    unknown = sorted(set(included) - set(known))
    if unknown:
        raise DatasetError(f"labels not in configs/labels.yaml: {unknown}")
    return [label for label in known if label in set(included)]


def encode_labels(values, labels: list[str]) -> np.ndarray:
    """Label names -> class indices of ``labels`` (a name outside it is an error)."""
    index = {name: i for i, name in enumerate(labels)}
    try:
        return np.array([index[value] for value in values], dtype=int)
    except KeyError as error:
        raise DatasetError(f"label {error.args[0]!r} is not one of {labels}") from None


def label_mapping(labels: list[str], excluded: dict[str, int]) -> dict:
    """label_mapping.json: model index <-> name, plus the stable labels.yaml ids."""
    yaml_ids = {name: i for i, name in enumerate(get_labels())}
    return {
        "classes": labels,
        "index": {name: i for i, name in enumerate(labels)},
        "labels_yaml_id": {name: yaml_ids[name] for name in labels},
        "excluded_classes": excluded,
    }


# ---- feature cleaning (TRAIN only) --------------------------------------------------------


def clean_features(
    train: pd.DataFrame, features: list[str], threshold: float
) -> tuple[list[str], list[dict]]:
    """(kept features in dictionary order, dropped [{feature, reason, detail}]).

    ``train`` must be the training rows only - the caller guarantees that, the
    tests check it (a feature constant on train but not on test is dropped).
    """
    dropped = []
    kept = []
    for name in features:
        values = train[name]
        if values.nunique(dropna=False) <= 1:
            dropped.append(
                {"feature": name, "reason": "constant", "detail": f"always {values.iloc[0]:g}"}
            )
        else:
            kept.append(name)
    if len(kept) > 1:
        corr = train[kept].astype(float).corr().abs()
        removed: set[str] = set()
        for i, first in enumerate(kept):
            if first in removed:
                continue
            for second in kept[i + 1 :]:
                if second in removed:
                    continue
                r = corr.at[first, second]
                if np.isfinite(r) and r > threshold:
                    removed.add(second)
                    dropped.append(
                        {
                            "feature": second,
                            "reason": "correlated",
                            "detail": f"|r| = {r:.4f} with {first} (kept, earlier in dictionary)",
                        }
                    )
        kept = [name for name in kept if name not in removed]
    return kept, dropped


# ---- loading ------------------------------------------------------------------------------


def check_feature_table(columns: list[str], dictionary: dict) -> list[str]:
    """The feature columns of dom_features.csv; errors if they do not match the dictionary."""
    if columns[: len(ID_COLUMNS)] != ID_COLUMNS:
        raise DatasetError(f"dom_features.csv must start with {ID_COLUMNS}")
    in_csv = columns[len(ID_COLUMNS) :]
    in_file = [feature["name"] for feature in dictionary.get("features", [])]
    if in_csv != in_file:
        raise DatasetError(
            "dom_features.csv columns do not match its feature_dictionary.json "
            f"(extra {sorted(set(in_csv) - set(in_file))[:5]}, "
            f"missing {sorted(set(in_file) - set(in_csv))[:5]})"
        )
    current = load_dictionary()
    if (
        dictionary.get("feature_set_version") != current.feature_set_version
        or dictionary.get("dictionary_hash") != dictionary_hash()
        or in_csv != list(feature_names())
    ):
        raise DatasetError(
            f"the DOM features were made with another dictionary "
            f"({dictionary.get('feature_set_version')}, hash "
            f"{str(dictionary.get('dictionary_hash'))[:12]}) than configs/dom_features.yaml "
            f"({current.feature_set_version}, {dictionary_hash()[:12]}) - re-run "
            "extract_dom_features.py run"
        )
    return in_csv


def load_feature_table(version: str, features_dir: Path | None = None) -> pd.DataFrame:
    folder = features_dir or features_output_dir(version)
    csv_path, dictionary_path = folder / CSV_NAME, folder / DICTIONARY_NAME
    if not csv_path.is_file() or not dictionary_path.is_file():
        raise FileNotFoundError(
            f"no DOM features for {version} in {folder} - run: python "
            f"scripts/extract_dom_features.py run --version {version}"
        )
    table = pd.read_csv(
        csv_path, dtype={column: str for column in ID_COLUMNS}, keep_default_na=False
    )
    names = check_feature_table(list(table.columns), json.loads(dictionary_path.read_text("utf-8")))
    values = table[names].apply(pd.to_numeric, errors="coerce")
    if values.isna().to_numpy().any():
        bad = table.loc[values.isna().any(axis=1), "sample_id"].tolist()
        raise DatasetError(f"non-numeric / empty feature values for {bad[:5]}")
    table[names] = values
    return table


def prepare_dataset(
    version: str,
    correlation_threshold: float = 0.98,
    features_dir: Path | None = None,
    splits_root: Path | None = None,
    manifests: Path | None = None,
    source: FeatureSource | None = None,
) -> DomDataset:
    """Join features + split, encode labels, clean features on train. Nothing is written.

    ``source`` picks the feature table (default: Part 3's DOM features)."""
    source = source or default_source()
    split, info = load_split(version, splits_root)
    if manifests is not None:
        check_current(info, manifests, version)
    table = source.load_table(version, features_dir)
    names = list(source.names())

    included = split[split["split"] != EXCLUDED]
    frame = included.merge(
        table.drop(columns=["language", "cluster_id"]),
        on="sample_id",
        how="left",
        suffixes=("", "_features"),
        indicator=True,
    )
    missing = frame.loc[frame["_merge"] != "both", "sample_id"].tolist()
    if missing:
        raise DatasetError(
            f"{len(missing)} split sample(s) have no {source.key} features (e.g. {missing[:5]}) - "
            f"run {source.produce_hint.format(version=version)}"
        )
    mismatch = frame.loc[frame["label"] != frame["label_features"], "sample_id"].tolist()
    if mismatch:
        raise DatasetError(f"label differs between split and features for {mismatch[:5]}")
    frame = frame.drop(columns=["_merge", "label_features"])

    labels = label_order(info.get("included_classes") or sorted(included["label"].unique()))
    frame["y"] = encode_labels(frame["label"], labels)
    folds = load_cv_folds(version, splits_root).set_index("sample_id")["fold"]
    frame["fold"] = frame["sample_id"].map(folds).fillna(-1).astype(int)
    pool = frame["split"].isin(["train", "val"])
    if (frame.loc[pool, "fold"] < 0).any() or (frame.loc[~pool, "fold"] >= 0).any():
        raise DatasetError("cv_folds.csv does not match split.csv (re-run the split)")

    kept, dropped = clean_features(frame[frame["split"] == "train"], names, correlation_threshold)
    columns = ["sample_id", "label", "language", "cluster_id", "split", "fold", "y"] + names
    return DomDataset(
        version=version,
        frame=frame[columns].reset_index(drop=True),
        all_features=names,
        features=kept,
        labels=labels,
        dropped=dropped,
        split_info=info,
        feature_set_version=source.feature_set_version(),
        dictionary_hash=source.fingerprint(),
    )
