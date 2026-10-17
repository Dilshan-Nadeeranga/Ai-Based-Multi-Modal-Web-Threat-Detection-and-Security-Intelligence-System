"""Everything the fusion needs for one version, aligned page by page.

Part 9: Tri-modal fusion + ablation study (Batch A).

- the shared split (labels, train / val / test, CV fold) - ``oof.load_reference``
- each available arm's OOF / test probabilities - ``oof.load_all`` (stale files refused,
  a missing optional arm such as text_xlmr is simply listed as missing)
- the RAW DOM and behavior feature tables for the hybrid model (all features; the
  hybrid decides its own cleaning on its training folds). Columns are prefixed with the
  arm ("dom.node_count", "behavior.fetch_count") because 4 names exist in both tables
  (e.g. inline_script_count) and the prefix is what groups SHAP values per arm.
- the Part 5A page language bucket (en / si / ta / mixed / other) for per-language results
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from c2_analyzer.fusion.common import FusionConfig
from c2_analyzer.fusion.oof import ArmOof, Reference, load_all, load_reference
from c2_analyzer.fusion.strategies import FusionInputs


def feature_sources() -> dict:
    from c2_analyzer.behavior.baseline import BEHAVIOR_SOURCE
    from c2_analyzer.classifiers.dom_baseline.sources import DOM_SOURCE

    return {"dom": DOM_SOURCE, "behavior": BEHAVIOR_SOURCE}


def load_features(version: str, arms: list[str]) -> dict[str, pd.DataFrame]:
    """arm -> frame indexed by sample_id with prefixed raw feature columns (checked tables)."""
    sources, tables = feature_sources(), {}
    for arm in arms:
        if arm not in sources:
            continue
        source = sources[arm]
        table = source.load_table(version, None)  # refuses tables made with other rules
        names = list(source.names())
        frame = table.set_index("sample_id")[names].astype(float)
        frame.columns = [f"{arm}.{name}" for name in names]
        tables[arm] = frame
    return tables


def load_languages(version: str) -> dict[str, str]:
    """sample_id -> Part 5A language bucket ("unknown" for all if the text is unavailable)."""
    try:
        from c2_analyzer.nlp.dataset import build_examples

        return {row["sample_id"]: row["language"] for row in build_examples(version).examples}
    except (FileNotFoundError, ValueError):
        return {}


@dataclass
class FusionData:
    ref: Reference
    oofs: dict[str, ArmOof]
    missing: list[str]
    config: FusionConfig
    features: dict[str, pd.DataFrame] = field(default_factory=dict)
    languages: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, version: str, config: FusionConfig | None = None, oof_dir=None) -> FusionData:
        config = config or FusionConfig.load()
        ref = load_reference(version)
        oofs, missing = load_all(ref, config, oof_dir)
        tabular = [arm for arm in oofs if not config.is_text(arm)]
        return cls(
            ref=ref,
            oofs=oofs,
            missing=missing,
            config=config,
            features=load_features(version, tabular),
            languages=load_languages(version),
        )

    @property
    def labels(self) -> list[str]:
        return self.ref.labels

    @property
    def available(self) -> list[str]:
        return [arm for arm in self.config.arms if arm in self.oofs]

    def ids(self, part: str) -> list[str]:
        frame = self.ref.pool if part == "pool" else self.ref.test
        return frame["sample_id"].tolist()

    def y(self, part: str) -> np.ndarray:
        frame = self.ref.pool if part == "pool" else self.ref.test
        return frame["y"].to_numpy(dtype=int)

    def folds(self) -> np.ndarray:
        return self.ref.pool["fold"].to_numpy(dtype=int)

    def language_of(self, ids: list[str]) -> list[str]:
        return [self.languages.get(sample_id, "unknown") for sample_id in ids]

    def inputs(self, arms: list[str], ids: list[str]) -> FusionInputs:
        """FusionInputs of ``arms`` for the pages ``ids`` (rows in that order)."""
        tabular = [arm for arm in arms if arm in self.features]
        frames = [self.features[arm].loc[ids] for arm in tabular]
        features = pd.concat(frames, axis=1) if frames else None
        return FusionInputs(
            arms=list(arms),
            probs={arm: self.oofs[arm].proba(ids) for arm in arms},
            labels=self.labels,
            text_arms=[arm for arm in arms if self.config.is_text(arm)],
            features=None if features is None else features.to_numpy(dtype=float),
            feature_names=[] if features is None else list(features.columns),
        )
