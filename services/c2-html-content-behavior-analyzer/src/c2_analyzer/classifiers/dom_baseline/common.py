"""Settings, paths and saved-model helpers shared by the DOM baseline modules.

Part 4: DOM baseline classifier ("Baseline 1": DOM-only structural classification).

    configs/dom_baseline.yaml                     models, grids, thresholds
    models/dom_baseline/<version>/<model>.joblib  trained model bundles (git-ignored)
    models/dom_baseline/<version>/model_card.json what the models are (tracked)
    reports/dom_baseline/<version>/               results.json/.md, figures, CSVs (tracked)

A saved model is a plain dict ("bundle"), not a custom class, so loading it
never depends on how this package's classes looked when it was saved:
    {"estimator", "model", "display_name", "params", "features", "labels",
     "cv", "grid", "split_fingerprint", "feature_set_version", "dictionary_hash",
     "seed", "trained_at", "library_versions"}
"""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib

from c2_analyzer.config import load_yaml_config, resolve_path
from c2_analyzer.dom.dictionary import load_dictionary

MODEL_NAMES: tuple[str, ...] = ("logreg", "random_forest", "xgboost")
ALIASES = {
    "logreg": "logreg",
    "lr": "logreg",
    "logistic_regression": "logreg",
    "rf": "random_forest",
    "random_forest": "random_forest",
    "xgb": "xgboost",
    "xgboost": "xgboost",
}


@dataclass(frozen=True)
class BaselineConfig:
    """configs/dom_baseline.yaml + the ``dom_baseline:`` paths of configs/config.yaml."""

    models: dict[str, dict[str, Any]]
    seed: int = 42
    n_jobs: int = 1
    selection_metric: str = "macro_f1"
    correlation_threshold: float = 0.98
    benign_fpr_target: float = 0.02
    min_language_support: int = 10
    top_n: int = 15
    permutation_repeats: int = 20
    contributions: int = 5
    models_dir: Path = Path("models/dom_baseline")
    reports_dir: Path = Path("reports/dom_baseline")
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls) -> BaselineConfig:
        main = load_yaml_config("config")
        paths = main.get("dom_baseline", {})
        raw = load_yaml_config("dom_baseline")
        evaluation = raw.get("evaluation", {})
        importance = raw.get("importance", {})
        return cls(
            models=raw["models"],
            seed=int(main.get("project", {}).get("random_seed", 42)),
            n_jobs=int(paths.get("n_jobs", 1)),
            selection_metric=str(raw.get("selection_metric", "macro_f1")),
            correlation_threshold=float(
                raw.get("feature_cleaning", {}).get("correlation_threshold", 0.98)
            ),
            benign_fpr_target=float(evaluation.get("benign_fpr_target", 0.02)),
            min_language_support=int(evaluation.get("min_language_support", 10)),
            top_n=int(importance.get("top_n", 15)),
            permutation_repeats=int(importance.get("permutation_repeats", 20)),
            contributions=int(importance.get("contributions", 5)),
            models_dir=resolve_path(Path(paths.get("models_dir", "models/dom_baseline"))),
            reports_dir=resolve_path(Path(paths.get("reports_dir", "reports/dom_baseline"))),
            raw=raw,
        )

    def jobs(self, model: str) -> int:
        """Threads for one model: its own ``n_jobs`` in dom_baseline.yaml, else the global one."""
        return int(self.models.get(model, {}).get("n_jobs", self.n_jobs))

    def display_name(self, model: str) -> str:
        return str(self.models.get(model, {}).get("display_name", model))


def parse_models(text: str | None) -> list[str]:
    """ "logreg,rf,xgb" -> ["logreg", "random_forest", "xgboost"] (dictionary order kept)."""
    if not text:
        return list(MODEL_NAMES)
    chosen = set()
    for part in text.split(","):
        name = ALIASES.get(part.strip().lower())
        if name is None:
            raise ValueError(f"unknown model {part!r}; use logreg, rf, xgb")
        chosen.add(name)
    return [name for name in MODEL_NAMES if name in chosen]


def model_dir(config: BaselineConfig, version: str) -> Path:
    return config.models_dir / version


def report_dir(config: BaselineConfig, version: str) -> Path:
    return config.reports_dir / version


def bundle_path(config: BaselineConfig, version: str, model: str) -> Path:
    return model_dir(config, version) / f"{model}.joblib"


def save_bundle(bundle: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".joblib.tmp")
    joblib.dump(bundle, temp)
    temp.replace(path)  # atomic: a crash never leaves half a model
    return path


def load_bundles(config: BaselineConfig, version: str) -> dict[str, dict[str, Any]]:
    """The trained bundles of a version, in MODEL_NAMES order (missing ones are skipped).

    joblib files are pickles: only ever load the ones this project wrote itself.
    """
    bundles = {}
    for model in MODEL_NAMES:
        path = bundle_path(config, version, model)
        if path.is_file():
            bundles[model] = joblib.load(path)
    return bundles


def readable_name(feature: str, width: int = 48) -> str:
    """'node_count' -> 'Elements plus non-empty text nodes [node_count]' (for plots/tables).

    The first sentence of the dictionary description, shortened, plus the name
    (the name keeps it unambiguous; the description keeps it human).
    """
    specs = {spec.name: spec for spec in load_dictionary().features}
    spec = specs.get(feature)
    if spec is None:
        return feature
    first = spec.description.split(". ")[0].rstrip(".")
    if len(first) > width:
        first = first[: width - 3].rstrip() + "..."
    return f"{first} [{feature}]"


def describe_feature(feature: str) -> str:
    specs = {spec.name: spec for spec in load_dictionary().features}
    return specs[feature].description if feature in specs else feature


def library_versions() -> dict[str, str]:
    """Versions that decide whether a saved model can be loaded and gives the same numbers."""
    import numpy
    import pandas
    import sklearn
    import xgboost

    versions = {
        "python": platform.python_version(),
        "numpy": numpy.__version__,
        "pandas": pandas.__version__,
        "scikit-learn": sklearn.__version__,
        "xgboost": xgboost.__version__,
        "joblib": joblib.__version__,
    }
    try:
        import shap

        versions["shap"] = shap.__version__
    except ImportError:  # pragma: no cover - shap is in requirements.txt
        pass
    return versions
