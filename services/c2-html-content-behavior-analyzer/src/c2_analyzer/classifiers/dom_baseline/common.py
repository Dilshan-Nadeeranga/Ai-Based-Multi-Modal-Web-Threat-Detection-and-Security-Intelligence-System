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

Reuse by later parts (ablation study): the whole protocol (split, grids, CV
selection, one test evaluation, importance, report, model card) is the same
for every modality; only the FEATURE TABLE differs. A ``FeatureSource`` says
which table to load and how to name / describe / fingerprint its features
(``sources.DOM_SOURCE`` is the default; Part 8's behavior-only baseline passes
its own). ``BaselineConfig.load(source)`` reads that source's paths from
configs/config.yaml (``dom_baseline:`` / ``behavior_baseline:``).
"""

from __future__ import annotations

import platform
from collections.abc import Callable
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
class FeatureSource:
    """Which feature table a baseline is trained on, and how its features are named.

    ``load_table(version, folder)`` returns the checked table (ID columns + the
    ``names()`` columns); ``fingerprint()`` changes whenever the feature
    definitions change (stored as ``dictionary_hash`` in every bundle, so a model
    trained on other definitions is refused, never silently reused).
    """

    key: str  # "dom", "behavior"
    title: str  # report title: "DOM baseline (Baseline 1)"
    heading: str  # "Baseline 1 - DOM-only structural classification"
    short: str  # console: "Baseline 1 - DOM only"
    card_name: str
    intended_use: str
    config_section: str  # configs/config.yaml section with models_dir / reports_dir / n_jobs
    default_models_dir: str
    default_reports_dir: str
    command: str  # "scripts/train_dom_baseline.py" (+ " all --version v" etc.)
    train_command: str  # "{command} train --version {version}"
    all_command: str  # "{command} all --version {version}"
    produce_hint: str  # how to make the feature table: "extract_dom_features.py run ..."
    load_table: Callable[[str, Path | None], Any]
    names: Callable[[], list[str]]
    descriptions: Callable[[], dict[str, str]]
    feature_set_version: Callable[[], str]
    fingerprint: Callable[[], str]

    def train_hint(self, version: str) -> str:
        return self.train_command.format(command=self.command, version=version)

    def all_hint(self, version: str) -> str:
        return self.all_command.format(command=self.command, version=version)


def default_source() -> FeatureSource:
    from c2_analyzer.classifiers.dom_baseline.sources import DOM_SOURCE

    return DOM_SOURCE


@dataclass(frozen=True)
class BaselineConfig:
    """configs/dom_baseline.yaml + the paths of the source's section of configs/config.yaml
    (``dom_baseline:`` for the DOM baseline)."""

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
    source: FeatureSource | None = None  # None = the DOM features (Part 4)

    @classmethod
    def load(cls, source: FeatureSource | None = None) -> BaselineConfig:
        source = source or default_source()
        main = load_yaml_config("config")
        paths = main.get(source.config_section, {})
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
            models_dir=resolve_path(Path(paths.get("models_dir", source.default_models_dir))),
            reports_dir=resolve_path(Path(paths.get("reports_dir", source.default_reports_dir))),
            raw=raw,
            source=source,
        )

    @property
    def features(self) -> FeatureSource:
        return self.source or default_source()

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


def readable_name(feature: str, width: int = 48, source: FeatureSource | None = None) -> str:
    """'node_count' -> 'Elements plus non-empty text nodes [node_count]' (for plots/tables).

    The first sentence of the dictionary description, shortened, plus the name
    (the name keeps it unambiguous; the description keeps it human).
    """
    description = (source or default_source()).descriptions().get(feature)
    if description is None:
        return feature
    first = description.split(". ")[0].rstrip(".")
    if len(first) > width:
        first = first[: width - 3].rstrip() + "..."
    return f"{first} [{feature}]"


def describe_feature(feature: str, source: FeatureSource | None = None) -> str:
    return (source or default_source()).descriptions().get(feature, feature)


def dom_descriptions() -> dict[str, str]:
    return {spec.name: spec.description for spec in load_dictionary().features}


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
