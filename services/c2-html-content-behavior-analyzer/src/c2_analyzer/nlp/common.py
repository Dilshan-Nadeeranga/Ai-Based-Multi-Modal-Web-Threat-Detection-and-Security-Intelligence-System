"""Shared settings and paths of the Part 6A text models (repo side).

Part 6: XLM-R content classification (6A, page level).

``configs/xlmr.yaml`` holds every tunable; the base model NAME comes from .env
``XLMR_MODEL_NAME`` (``config.Settings.xlmr_model_name``) so a team member can point it
at another checkpoint without editing configs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from c2_analyzer.config import get_settings, load_yaml_config, resolve_path

XLMR_DISPLAY = "XLM-R (fine-tuned)"
BASELINE_NAME = "tfidf_logreg"
BASELINE_DISPLAY = "TF-IDF char 2-5 + LogReg"


@dataclass
class XlmrConfig:
    raw: dict[str, Any]
    model_name: str
    source: Path  # the configs/xlmr.yaml it was read from (copied into the Colab bundle)

    @classmethod
    def load(cls, config_dir: Path | None = None) -> XlmrConfig:
        settings = get_settings()
        directory = config_dir or resolve_path(settings.config_dir)
        raw = load_yaml_config("xlmr", directory)
        return cls(raw=raw, model_name=settings.xlmr_model_name, source=directory / "xlmr.yaml")

    def _path(self, key: str) -> Path:
        return resolve_path(Path(self.raw["paths"][key]))

    @property
    def max_length(self) -> int:
        return int(self.raw["max_length"])

    @property
    def seeds(self) -> list[int]:
        return [int(s) for s in self.raw["seeds"]]

    @property
    def min_language_support(self) -> int:
        return int(self.raw["evaluation"]["min_language_support"])

    @property
    def languages(self) -> list[str]:
        return list(self.raw["evaluation"]["languages"])

    @property
    def inference(self) -> dict[str, Any]:
        return dict(self.raw["inference"])

    @property
    def baseline(self) -> dict[str, Any]:
        return dict(self.raw["text_baseline"])

    def training_config(self) -> dict[str, Any]:
        """The dict the portable train.py reads (same keys as configs/xlmr.yaml)."""
        return {**self.raw, "model_name": self.model_name}

    def models_dir(self, version: str) -> Path:
        return self._path("models_dir") / version

    def reports_dir(self, version: str) -> Path:
        return self._path("reports_dir") / version

    def baseline_models_dir(self, version: str) -> Path:
        return self._path("baseline_models_dir") / version

    def baseline_reports_dir(self, version: str) -> Path:
        return self._path("baseline_reports_dir") / version

    @property
    def bundle_dir(self) -> Path:
        return self._path("bundle_dir")

    def smoke_dir(self, version: str) -> Path:
        return self._path("smoke_dir") / version
