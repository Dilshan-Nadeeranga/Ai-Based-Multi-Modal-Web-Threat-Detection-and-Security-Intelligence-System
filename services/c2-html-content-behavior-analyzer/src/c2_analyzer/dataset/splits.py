"""The shared train / validation / test split of a frozen dataset version.

Part 4 (task 3), but used by EVERY later part: Part 6 (NLP-only), Part 8
(behavior-only) and the fused model all read the same files, so the ablation
study compares the modalities on exactly the same test pages.

    data/splits/<version>/split.csv      sample_id, label, language, cluster_id, split
    data/splits/<version>/split.json     seed, ratios, counts per split x label x language,
                                         excluded classes, manifest fingerprint, ...
    data/splits/<version>/cv_folds.csv   sample_id, label, language, cluster_id, fold
                                         (grouped stratified K-fold over train+val)

Why it is built this way (viva):
- **By sample_id, not by modality.** The split only looks at the manifest
  (ids, labels, languages, clusters), never at DOM/text/JS features, so one
  split serves every modality.
- **Grouped by near-duplicate cluster (no leakage).** Part 1 groups copies of
  the same phishing kit into one cluster_id. If one copy were in train and
  another in test, the model would be tested on a page it has effectively
  already seen and the score would be too optimistic. So a cluster always goes
  to exactly one split.
- **Stratified by label x language.** Every split gets about the same class
  mix, and the few Sinhala/Tamil pages are spread over train/val/test instead
  of landing in one split by chance.
- **How:** StratifiedGroupKFold cuts the data into ``units`` (20) small
  pieces of ~5 %, each stratified and cluster-pure. A seeded search then picks
  which pieces become val (15 %) and test (15 %) so that the ratios, the label
  mix and the Sinhala/Tamil spread are closest to the targets. The actual
  ratios are reported (they cannot be exact: clusters are not cut).
- **Tiny classes are excluded**, not silently mixed in: a class with fewer than
  ``min_samples_per_class`` pages (v0.1: fake_ecommerce, crypto_scam) cannot
  be learned or evaluated meaningfully. Its pages get split="excluded" and the
  class is listed in split.json, so every result says "pilot, N classes".
- **The test split is for the final evaluation only.** Model selection uses
  ``cv_folds.csv`` (grouped stratified 5-fold over train+val), which is more
  reliable than one small validation split and never contains a test page.
- **Never overwritten by accident:** an existing split is kept unless
  ``force=True``, and a split is refused when the manifest's files no longer
  verify (a split of a broken dataset would not be reproducible).
"""

from __future__ import annotations

import hashlib
import json
import warnings
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from c2_analyzer.config import get_labels, get_languages, load_yaml_config, resolve_path
from c2_analyzer.dataset.manifest import check_files, manifest_paths
from c2_analyzer.utils.io import atomic_write_csv, write_json

SPLITS = ("train", "val", "test")
EXCLUDED = "excluded"
SPLIT_COLUMNS = ["sample_id", "label", "language", "cluster_id", "split"]
FOLD_COLUMNS = ["sample_id", "label", "language", "cluster_id", "fold"]


class SplitError(RuntimeError):
    """The split cannot be made or used (broken manifest, stale split, too little data)."""


@dataclass(frozen=True)
class SplitConfig:
    """The ``split:`` section of configs/config.yaml (+ the project seed)."""

    train: float = 0.70
    val: float = 0.15
    test: float = 0.15
    seed: int = 42
    stratify_by: tuple[str, ...] = ("label", "language")
    group_by: str = "cluster_id"
    min_samples_per_class: int = 15
    units: int = 20
    search_iterations: int = 2000
    cv_folds: int = 5

    @classmethod
    def from_config(cls) -> SplitConfig:
        config = load_yaml_config("config")
        section = config.get("split", {})
        defaults = cls()
        return cls(
            train=float(section.get("train", defaults.train)),
            val=float(section.get("val", defaults.val)),
            test=float(section.get("test", defaults.test)),
            seed=int(config.get("project", {}).get("random_seed", defaults.seed)),
            stratify_by=tuple(section.get("stratify_by", defaults.stratify_by)),
            group_by=str(section.get("group_by", defaults.group_by)),
            min_samples_per_class=int(
                section.get("min_samples_per_class", defaults.min_samples_per_class)
            ),
            units=int(section.get("units", defaults.units)),
            search_iterations=int(section.get("search_iterations", defaults.search_iterations)),
            cv_folds=int(section.get("cv_folds", defaults.cv_folds)),
        )

    @property
    def ratios(self) -> dict[str, float]:
        return {"train": self.train, "val": self.val, "test": self.test}


# ---- paths ------------------------------------------------------------------------------


def splits_root() -> Path:
    """data/splits/ (``paths.splits_dir`` in configs/config.yaml)."""
    paths = load_yaml_config("config").get("paths", {})
    return resolve_path(Path(paths.get("splits_dir", "data/splits")))


def split_paths(version: str, root: Path | None = None) -> tuple[Path, Path, Path]:
    """(split.csv, split.json, cv_folds.csv) of a version (the version name is validated)."""
    manifest_paths(Path("."), version)  # raises ValueError for odd version names
    folder = (root or splits_root()) / version
    return folder / "split.csv", folder / "split.json", folder / "cv_folds.csv"


# ---- the assignment (pure functions, no files) ------------------------------------------


def _groups(frame: pd.DataFrame, group_by: str) -> pd.Series:
    """Group id per row; a page without a cluster is its own group."""
    groups = frame[group_by].astype(str) if group_by in frame else frame["sample_id"]
    return groups.where(groups.str.len() > 0, frame["sample_id"])


def _strata(frame: pd.DataFrame, columns: tuple[str, ...]) -> pd.Series:
    return frame[list(columns)].astype(str).agg("|".join, axis=1)


def _units(frame: pd.DataFrame, config: SplitConfig) -> tuple[np.ndarray, int]:
    """StratifiedGroupKFold pieces: unit index per row (each unit is cluster-pure)."""
    groups = _groups(frame, config.group_by)
    n_units = min(config.units, groups.nunique())
    if n_units < len(SPLITS):
        raise SplitError(f"only {groups.nunique()} cluster(s): too few to make three splits")
    folds = StratifiedGroupKFold(n_splits=n_units, shuffle=True, random_state=config.seed)
    unit = np.full(len(frame), -1)
    with warnings.catch_warnings():
        # expected: some label x language strata (e.g. 3 Tamil pages) are smaller than n_units
        warnings.filterwarnings("ignore", message="The least populated class", category=UserWarning)
        for index, (_, part) in enumerate(
            folds.split(np.zeros(len(frame)), _strata(frame, config.stratify_by), groups)
        ):
            unit[part] = index
    return unit, n_units


def _spread_languages() -> list[str]:
    """The low-resource languages whose placement matters (Sinhala, Tamil)."""
    return [code for code in get_languages(include_special=False) if code != "en"]


def _choose_units(frame: pd.DataFrame, unit: np.ndarray, n_units: int, config: SplitConfig):
    """Seeded search: which units become test / val (the rest is train).

    Cost (lower is better), all terms are shares so they are comparable:
    - distance of the split sizes from 70/15/15,
    - distance of each split's label mix from the overall label mix (+ a big
      penalty when a class that has >= 3 pages is missing from a split),
    - Sinhala/Tamil: a penalty for every split without one (when there are at
      least 3 such pages, one per split is possible) + distance from 70/15/15.
    """
    n_test = max(1, round(config.test * n_units))
    n_val = max(1, round(config.val * n_units))
    if n_test + n_val >= n_units:
        raise SplitError(f"{n_units} units are too few for val + test + train")
    targets = np.array([config.train, config.val, config.test])

    labels = sorted(frame["label"].unique())
    label_counts = np.zeros((n_units, len(labels)))
    for j, label in enumerate(labels):
        label_counts[:, j] = np.bincount(
            unit[(frame["label"] == label).to_numpy()], minlength=n_units
        )
    languages = [c for c in _spread_languages() if (frame["language"] == c).any()]
    language_counts = np.zeros((n_units, len(languages)))
    for j, language in enumerate(languages):
        mask = (frame["language"] == language).to_numpy()
        language_counts[:, j] = np.bincount(unit[mask], minlength=n_units)
    sizes = np.bincount(unit, minlength=n_units).astype(float)
    total = sizes.sum()
    label_share = label_counts.sum(axis=0) / total
    language_total = language_counts.sum(axis=0)

    def cost(test: np.ndarray, val: np.ndarray) -> float:
        member = np.zeros((3, n_units))
        member[2, test] = 1
        member[1, val] = 1
        member[0] = 1 - member[1] - member[2]
        size = member @ sizes  # (3,)
        value = np.abs(size / total - targets).sum()
        per_label = member @ label_counts  # (3, labels)
        value += np.abs(per_label / np.maximum(size[:, None], 1) - label_share).sum() / len(labels)
        value += 10.0 * ((per_label == 0) & (label_counts.sum(axis=0) >= 3)).sum()
        if languages:
            per_language = member @ language_counts  # (3, languages)
            value += 1.0 * ((per_language == 0) & (language_total >= 3)).sum()
            value += 0.5 * np.abs(per_language / language_total - targets[:, None]).sum()
        return float(value)

    rng = np.random.default_rng(config.seed)
    best, best_cost = None, np.inf
    for _ in range(max(1, config.search_iterations)):
        order = rng.permutation(n_units)
        test, val = order[:n_test], order[n_test : n_test + n_val]
        value = cost(test, val)
        if value < best_cost - 1e-12:
            best, best_cost = (set(test.tolist()), set(val.tolist())), value
    test_units, val_units = best
    return np.array(
        ["test" if u in test_units else "val" if u in val_units else "train" for u in unit]
    )


def excluded_classes(manifest: pd.DataFrame, min_samples: int) -> dict[str, int]:
    """Classes of configs/labels.yaml with fewer than ``min_samples`` pages (count per class)."""
    counts = manifest["label"].value_counts()
    return {
        label: int(counts.get(label, 0))
        for label in get_labels()
        if int(counts.get(label, 0)) < min_samples
    }


def assign_splits(manifest: pd.DataFrame, config: SplitConfig) -> pd.DataFrame:
    """Manifest rows + a ``split`` column (train / val / test / excluded), sorted by sample_id."""
    frame = manifest[SPLIT_COLUMNS[:-1]].astype(str).sort_values("sample_id").reset_index(drop=True)
    excluded = excluded_classes(frame, config.min_samples_per_class)
    included = ~frame["label"].isin(excluded)
    if included.sum() == 0:
        raise SplitError(
            f"no class has at least {config.min_samples_per_class} pages - nothing to train on"
        )
    frame["split"] = EXCLUDED
    kept = frame[included].reset_index(drop=True)
    unit, n_units = _units(kept, config)
    frame.loc[included.to_numpy(), "split"] = _choose_units(kept, unit, n_units, config)
    return frame


def make_cv_folds(split: pd.DataFrame, config: SplitConfig) -> pd.DataFrame:
    """Grouped stratified K-fold over train+val (test pages are never in a fold)."""
    pool = split[split["split"].isin(["train", "val"])].reset_index(drop=True)
    groups = _groups(pool, config.group_by)
    k = min(config.cv_folds, groups.nunique())
    if k < 2:
        raise SplitError("train+val has fewer than 2 clusters - no cross-validation possible")
    folds = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=config.seed)
    fold = np.full(len(pool), -1)
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="The least populated class", category=UserWarning)
        for index, (_, part) in enumerate(folds.split(np.zeros(len(pool)), pool["label"], groups)):
            fold[part] = index
    pool["fold"] = fold
    return pool[FOLD_COLUMNS]


def split_fingerprint(split: pd.DataFrame) -> str:
    """sha256 of (sample_id, split) pairs: two runs on the same split have the same value."""
    lines = sorted(f"{row.sample_id}|{row.split}" for row in split.itertuples())
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _nested_counts(frame: pd.DataFrame, *columns: str) -> dict:
    """{split: {label: {language: n}}} style counts (only non-zero cells)."""
    if len(columns) == 1:
        return {str(k): int(v) for k, v in frame[columns[0]].value_counts().sort_index().items()}
    return {
        str(key): _nested_counts(part, *columns[1:])
        for key, part in frame.groupby(columns[0], sort=True)
    }


def describe_split(split: pd.DataFrame, folds: pd.DataFrame, config: SplitConfig) -> dict:
    """Everything a reader needs to trust the split (it becomes split.json)."""
    included = split[split["split"] != EXCLUDED]
    total = len(included)
    actual = {name: round(int((included["split"] == name).sum()) / total, 4) for name in SPLITS}
    groups = _groups(included, config.group_by)
    spanning = int((included.assign(_g=groups).groupby("_g")["split"].nunique() > 1).sum())
    placement = {
        language: {
            name: int(((included["language"] == language) & (included["split"] == name)).sum())
            for name in SPLITS
        }
        for language in _spread_languages()
    }
    excluded = excluded_classes(split, config.min_samples_per_class)
    return {
        "seed": config.seed,
        "target_ratios": config.ratios,
        "actual_ratios": actual,
        "max_ratio_difference": round(max(abs(actual[n] - config.ratios[n]) for n in SPLITS), 4),
        "stratify_by": list(config.stratify_by),
        "group_by": config.group_by,
        "units": min(config.units, groups.nunique()),
        "search_iterations": config.search_iterations,
        "min_samples_per_class": config.min_samples_per_class,
        "included_classes": [label for label in get_labels() if label not in excluded],
        "excluded_classes": excluded,
        "pilot": bool(excluded),
        "total_included": total,
        "total_excluded": int((split["split"] == EXCLUDED).sum()),
        "counts": {name: int((included["split"] == name).sum()) for name in SPLITS},
        "counts_per_label": _nested_counts(included, "split", "label"),
        "counts_per_language": _nested_counts(included, "split", "language"),
        "counts_per_label_language": _nested_counts(included, "split", "label", "language"),
        "language_placement": placement,
        "clusters": int(groups.nunique()),
        "clusters_in_two_splits": spanning,
        "cv_folds": int(folds["fold"].nunique()),
        "cv_counts_per_label": _nested_counts(folds, "fold", "label"),
        "split_fingerprint": split_fingerprint(split),
    }


# ---- files ------------------------------------------------------------------------------


def create_split(
    version: str,
    manifests: Path,
    raw_dir: Path,
    root: Path | None = None,
    force: bool = False,
    config: SplitConfig | None = None,
) -> dict:
    """Make and save the split of a frozen version. Returns the split.json content."""
    config = config or SplitConfig.from_config()
    csv_path, json_path, folds_path = split_paths(version, root)
    if (csv_path.exists() or json_path.exists()) and not force:
        raise FileExistsError(
            f"a split for {version} already exists ({csv_path.parent}); every later part "
            "depends on it - use --force only if you really want a new one"
        )
    manifest_csv, manifest_json = manifest_paths(manifests, version)
    if not manifest_csv.is_file() or not manifest_json.is_file():
        raise FileNotFoundError(f"no frozen manifest for {version} in {manifests}")
    manifest = pd.read_csv(manifest_csv, dtype=str, keep_default_na=False)
    missing, changed = check_files(raw_dir, manifest)
    if missing or changed:
        raise SplitError(
            f"manifest {version} no longer verifies: {len(missing)} file(s) missing "
            f"{missing[:5]}, {len(changed)} changed {changed[:5]} (dataset_stats.py verify)"
        )
    manifest_info = json.loads(manifest_json.read_text(encoding="utf-8"))

    split = assign_splits(manifest, config)
    folds = make_cv_folds(split, config)
    info = {
        "version": version,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "manifest": {
            "fingerprint": manifest_info.get("fingerprint"),
            "created_at": manifest_info.get("created_at"),
            "total": len(manifest),
        },
        **describe_split(split, folds, config),
    }
    atomic_write_csv(split, csv_path, SPLIT_COLUMNS)
    atomic_write_csv(folds, folds_path, FOLD_COLUMNS)
    write_json(info, json_path)
    return info


def load_split(version: str, root: Path | None = None) -> tuple[pd.DataFrame, dict]:
    """(split.csv rows, split.json) of a version; FileNotFoundError if not made yet."""
    csv_path, json_path, _ = split_paths(version, root)
    if not csv_path.is_file() or not json_path.is_file():
        raise FileNotFoundError(
            f"no split for {version} - run: python scripts/train_dom_baseline.py split "
            f"--version {version}"
        )
    split = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    return split, json.loads(json_path.read_text(encoding="utf-8"))


def load_cv_folds(version: str, root: Path | None = None) -> pd.DataFrame:
    _, _, folds_path = split_paths(version, root)
    if not folds_path.is_file():
        raise FileNotFoundError(f"no cv_folds.csv for {version} (re-run the split)")
    folds = pd.read_csv(folds_path, dtype=str, keep_default_na=False)
    folds["fold"] = folds["fold"].astype(int)
    return folds


def check_current(info: dict, manifests: Path, version: str) -> None:
    """Refuse a split whose manifest changed since it was made (it would be stale)."""
    _, manifest_json = manifest_paths(manifests, version)
    if not manifest_json.is_file():
        raise FileNotFoundError(f"no frozen manifest for {version} in {manifests}")
    current = json.loads(manifest_json.read_text(encoding="utf-8")).get("fingerprint")
    if current != info.get("manifest", {}).get("fingerprint"):
        raise SplitError(
            f"the split of {version} was made from a different manifest - re-run the split"
        )
