"""Settings, arm names and paths shared by the fusion modules.

Part 9: Tri-modal fusion + ablation study (Batch A).

    configs/fusion.yaml                       arms, strategies, operating point, bootstrap
    data/processed/fusion/<v>/oof_<arm>.csv   out-of-fold probabilities per arm (oof.py)
    models/fusion/<v>/                        the chosen fusion model + model_card.json
    reports/ablation/<v>/                     ablation.{md,json} + figures

An "arm" is one single-modality model of the ablation study (DOM-only, Behavior-only,
Text TF-IDF, Text XLM-R). Every arm numbers the classes the same way (Part 4's
label order), so a probability column ``p_<class>`` means the same thing in every file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from c2_analyzer.config import load_yaml_config, resolve_path

ARM_ORDER: tuple[str, ...] = ("dom", "behavior", "text_tfidf", "text_xlmr")
STRATEGY_ORDER: tuple[str, ...] = ("mean", "weighted", "stacking", "hybrid")
ID_COLUMNS = ["sample_id", "split", "fold"]


def prob_columns(labels: list[str]) -> list[str]:
    """['p_benign', 'p_phishing', ...] in class-index order."""
    return [f"p_{label}" for label in labels]


@dataclass(frozen=True)
class FusionConfig:
    """configs/fusion.yaml (+ the project seed)."""

    raw: dict[str, Any]
    seed: int = 42

    @classmethod
    def load(cls, config_dir: Path | None = None) -> FusionConfig:
        raw = load_yaml_config("fusion", config_dir)
        main = load_yaml_config("config", config_dir)
        return cls(raw=raw, seed=int(main.get("project", {}).get("random_seed", 42)))

    # ---- arms / strategies ------------------------------------------------------------

    @property
    def arms(self) -> list[str]:
        return [arm for arm in ARM_ORDER if arm in self.raw["arms"]]

    def arm_display(self, arm: str) -> str:
        return str(self.raw["arms"].get(arm, {}).get("display", arm))

    def is_text(self, arm: str) -> bool:
        return self.raw["arms"].get(arm, {}).get("kind") == "text"

    def is_optional(self, arm: str) -> bool:
        return bool(self.raw["arms"].get(arm, {}).get("optional", False))

    def strategy(self, name: str) -> dict[str, Any]:
        return dict(self.raw["strategies"][name])

    def strategy_display(self, name: str) -> str:
        return str(self.raw["strategies"].get(name, {}).get("display", name))

    # ---- settings ---------------------------------------------------------------------

    @property
    def benign_fpr_target(self) -> float:
        return float(self.raw["operating_point"]["benign_fpr_target"])

    @property
    def bootstrap(self) -> dict[str, Any]:
        return dict(self.raw["bootstrap"])

    @property
    def examples_per_bucket(self) -> int:
        return int(self.raw["complementarity"]["examples_per_bucket"])

    @property
    def top_features(self) -> int:
        return int(self.raw["explain"]["top_features"])

    @property
    def page_drivers(self) -> int:
        return int(self.raw["explain"]["page_drivers"])

    # ---- paths ------------------------------------------------------------------------

    def _path(self, key: str) -> Path:
        return resolve_path(Path(self.raw["paths"][key]))

    @property
    def oof_root(self) -> Path:
        return self._path("oof_dir")

    @property
    def models_root(self) -> Path:
        return self._path("models_dir")

    def oof_dir(self, version: str) -> Path:
        return self._path("oof_dir") / version

    def models_dir(self, version: str) -> Path:
        return self._path("models_dir") / version

    def reports_dir(self, version: str) -> Path:
        return self._path("reports_dir") / version
