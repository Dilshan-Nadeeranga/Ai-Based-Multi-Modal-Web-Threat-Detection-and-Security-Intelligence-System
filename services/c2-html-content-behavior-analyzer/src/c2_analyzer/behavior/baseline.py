"""Behavior-only baseline for the ablation study (js_features + behavior_features).

Part 8: Behavioral intent mapping (sources -> sinks).

Why: the thesis compares DOM-only, NLP-only, behavior-only and fused models on
the SAME pages. This module does not train anything itself - it reuses Part
4's code unchanged (split, small grids, grouped-CV model selection, one test
evaluation, importance, SHAP, report, model card) and only swaps the feature
table through a ``FeatureSource``:
    data/processed/js/<version>/js_features.csv              Part 7 (51 features)
  + data/processed/behavior/<version>/behavior_features.csv  Part 8 (intent vector)
joined on sample_id. Both tables are checked against their dictionaries AND
the current rule hashes (a table made with other rules is refused - re-run
analyze_js.py / map_behavior.py). Same split (data/splits/<version>), same
protocol, same report format:
    models/behavior_baseline/<version>/   reports/behavior_baseline/<version>/
plus ``comparison.{json,md}``: DOM-only (Part 4, same version) vs behavior-only.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import pandas as pd

from c2_analyzer.behavior import batch as part8
from c2_analyzer.behavior.rules import feature_names as behavior_names
from c2_analyzer.behavior.rules import load_behavior_rules
from c2_analyzer.behavior.rules import rules_hash as behavior_hash
from c2_analyzer.classifiers.dom_baseline.common import BaselineConfig, FeatureSource, report_dir
from c2_analyzer.classifiers.dom_baseline.data import DatasetError
from c2_analyzer.js_analyzer import batch as part7
from c2_analyzer.js_analyzer.rules import feature_names as js_names
from c2_analyzer.js_analyzer.rules import load_rules as load_js_rules
from c2_analyzer.js_analyzer.rules import rules_hash as js_hash
from c2_analyzer.utils.io import atomic_write_text, write_json

ID_COLUMNS = ["sample_id", "label", "language", "cluster_id"]
COMPARED = (
    "macro_f1",
    "weighted_f1",
    "accuracy",
    "balanced_accuracy",
    "roc_auc_ovr_macro",
    "benign_fpr",
)


def all_names() -> list[str]:
    names = list(js_names()) + list(behavior_names())
    if len(set(names)) != len(names):
        raise DatasetError("js_features and behavior_features share a feature name")
    return names


def descriptions() -> dict[str, str]:
    js = {spec.name: spec.description for spec in load_js_rules().features}
    behavior = {spec.name: spec.description for spec in load_behavior_rules().features}
    return {**js, **behavior}


def feature_set_version() -> str:
    return f"{load_js_rules().feature_set_version}+{load_behavior_rules().feature_set_version}"


def fingerprint() -> str:
    """Changes when either rule set (and so either vector) changes."""
    text = f"{js_hash()}|{behavior_hash()}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _table(
    folder: Path, csv_name: str, dictionary_name: str, names: list[str], current: str, how: str
):
    csv_path, dictionary_path = folder / csv_name, folder / dictionary_name
    if not csv_path.is_file() or not dictionary_path.is_file():
        raise FileNotFoundError(f"no {csv_name} in {folder} - run: python {how}")
    dictionary = json.loads(dictionary_path.read_text("utf-8"))
    if dictionary.get("rules_hash") != current:
        raise DatasetError(f"{csv_name} was made with other rules - re-run: python {how}")
    table = pd.read_csv(csv_path, dtype={c: str for c in ID_COLUMNS}, keep_default_na=False)
    if list(table.columns) != ID_COLUMNS + names:
        raise DatasetError(
            f"{csv_name} columns do not match the current feature list - re-run {how}"
        )
    values = table[names].apply(pd.to_numeric, errors="coerce")
    if values.isna().to_numpy().any():
        bad = table.loc[values.isna().any(axis=1), "sample_id"].tolist()
        raise DatasetError(f"non-numeric / empty values in {csv_name} for {bad[:5]}")
    table[names] = values
    return table


def load_table(version: str, features_dir: Path | None = None) -> pd.DataFrame:
    """js_features.csv + behavior_features.csv of a version, joined on sample_id.

    ``features_dir`` (optional) is a folder holding BOTH CSVs and dictionaries (tests)."""
    js_folder = features_dir or part7.output_dir(version)
    behavior_folder = features_dir or part8.output_dir(version)
    js = _table(
        js_folder,
        part7.CSV_NAME,
        part7.DICTIONARY_NAME,
        list(js_names()),
        js_hash(),
        f"scripts/analyze_js.py run --version {version}",
    )
    behavior = _table(
        behavior_folder,
        part8.CSV_NAME,
        part8.DICTIONARY_NAME,
        list(behavior_names()),
        behavior_hash(),
        f"scripts/map_behavior.py run --version {version}",
    )
    joined = js.merge(behavior, on="sample_id", how="inner", suffixes=("", "_behavior"))
    if (joined["label"] != joined["label_behavior"]).any():
        bad = joined.loc[joined["label"] != joined["label_behavior"], "sample_id"].tolist()
        raise DatasetError(f"label differs between js and behavior features for {bad[:5]}")
    return joined[ID_COLUMNS + all_names()].reset_index(drop=True)


BEHAVIOR_SOURCE = FeatureSource(
    key="behavior",
    title="Behavior-only baseline (JS + behavioral intent)",
    heading="Behavior-only classification (Part 7 JS features + Part 8 intent vector)",
    short="Behavior only (JS + intent vector)",
    card_name="C2 behavior-only baseline (Part 7 js_features + Part 8 behavior_features)",
    intended_use="Behavior-only arm of the ablation study (DOM-only vs NLP-only vs "
    "behavior-only vs fused). Research use on the C2 dataset; not a production detector.",
    config_section="behavior_baseline",
    default_models_dir="models/behavior_baseline",
    default_reports_dir="reports/behavior_baseline",
    command="scripts/map_behavior.py",
    train_command="{command} train-baseline --version {version}",
    all_command="{command} train-baseline --version {version}",
    produce_hint="scripts/map_behavior.py run --version {version}",
    load_table=load_table,
    names=all_names,
    descriptions=descriptions,
    feature_set_version=feature_set_version,
    fingerprint=fingerprint,
)


# ---- DOM-only vs behavior-only ---------------------------------------------------------------


def _best(results: dict) -> dict:
    model = results["models"][results["best_model"]]
    return {
        "model": model["display_name"],
        "cv_macro_f1": model["cv"]["mean"]["macro_f1"],
        "cv_macro_f1_std": model["cv"]["std"]["macro_f1"],
        **{key: model["test"].get(key) for key in COMPARED},
        "per_class_f1": {k: v["f1"] for k, v in model["test"]["per_class"].items()},
    }


def compare(version: str, behavior: dict, dom_reports: Path | None = None) -> dict:
    """Best model of each arm on the same test split (DOM results read from Part 4's report)."""
    dom_folder = dom_reports or report_dir(BaselineConfig.load(), version)
    dom_path = dom_folder / "results.json"
    dom = json.loads(dom_path.read_text("utf-8")) if dom_path.is_file() else None
    arms = {"behavior": _best(behavior)}
    notes = []
    if dom is None:
        notes.append(f"no DOM baseline for {version} ({dom_path}) - run train_dom_baseline.py all")
    else:
        arms = {"dom": _best(dom), **arms}
        if dom["split"].get("split_fingerprint") != behavior["split"].get("split_fingerprint"):
            notes.append("the two arms used different splits - not comparable")
    per_model = {}
    for arm, results in (("dom", dom), ("behavior", behavior)):
        if results is None:
            continue
        per_model[arm] = {
            name: {
                "display_name": model["display_name"],
                "cv_macro_f1": model["cv"]["mean"]["macro_f1"],
                **{key: model["test"].get(key) for key in COMPARED},
            }
            for name, model in results["models"].items()
        }
    return {
        "version": version,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "test_pages": behavior["split"]["counts"]["test"],
        "classes": behavior["classes"],
        "best": arms,
        "models": per_model,
        "features": {
            "behavior": behavior["features"]["used"],
            "dom": dom["features"]["used"] if dom else None,
        },
        "notes": notes,
    }


def _fmt(value) -> str:
    if value is None:
        return "—"
    return f"{value:.3f}"


def comparison_markdown(comparison: dict) -> str:
    best, labels = comparison["best"], comparison["classes"]
    names = {"dom": "DOM-only (Part 4)", "behavior": "Behavior-only (Part 7+8)"}
    lines = [
        f"# DOM-only vs Behavior-only - {comparison['version']}",
        "",
        f"Same shared split, same protocol (grouped-CV model selection on train+val, ONE test "
        f"evaluation on {comparison['test_pages']} pages). Best model of each arm by CV macro-F1.",
        "",
        "| arm | best model | features used | CV macro-F1 | test macro-F1 | weighted-F1 | accuracy "
        "| balanced acc. | ROC-AUC | benign FPR |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for arm, row in best.items():
        fpr = row["benign_fpr"]
        lines.append(
            f"| {names[arm]} | {row['model']} | {comparison['features'][arm]} | "
            f"{row['cv_macro_f1']:.3f} +/- {row['cv_macro_f1_std']:.3f} | "
            f"{_fmt(row['macro_f1'])} | "
            f"{_fmt(row['weighted_f1'])} | {_fmt(row['accuracy'])} | "
            f"{_fmt(row['balanced_accuracy'])} | {_fmt(row['roc_auc_ovr_macro'])} | "
            f"{'—' if fpr is None else f'{100 * fpr:.1f} %'} |"
        )
    lines += [
        "",
        "Per-class test F1 (best model of each arm):",
        "",
        "| class | " + " | ".join(names[a] for a in best) + " |",
        "|---|" + "---|" * len(best),
    ]
    for label in labels:
        lines.append(
            f"| {label} | "
            + " | ".join(_fmt(best[a]["per_class_f1"].get(label)) for a in best)
            + " |"
        )
    lines += ["", "All models (test macro-F1):", ""]
    for arm, models in comparison["models"].items():
        lines.append(
            f"- {names[arm]}: "
            + ", ".join(f"{m['display_name']} {_fmt(m['macro_f1'])}" for m in models.values())
        )
    if comparison["notes"]:
        lines += ["", "Notes:"] + [f"- {note}" for note in comparison["notes"]]
    lines.append("")
    return "\n".join(lines)


def write_comparison(comparison: dict, folder: Path) -> list[Path]:
    json_path, md_path = folder / "comparison.json", folder / "comparison.md"
    write_json(comparison, json_path)
    atomic_write_text(comparison_markdown(comparison), md_path)
    return [json_path, md_path]
