"""Evaluate the trained baselines once on test and write every Part 4 output.

Part 4: DOM baseline classifier (tasks 7-9 + outputs).

    reports/dom_baseline/<version>/results.json        everything below, machine-readable
    reports/dom_baseline/<version>/results.md          "Baseline 1" table for the thesis + details
    reports/dom_baseline/<version>/misclassified.csv   test pages each model got wrong
    reports/dom_baseline/<version>/dropped_features.csv
    reports/dom_baseline/<version>/figures/            confusion matrices, importance, SHAP
    models/dom_baseline/<version>/model_card.json      what the saved models are

Before anything is evaluated, every saved model is checked against the
current data (same split, same features, same classes, same dictionary). A
model trained on an older split or feature list must be retrained, never
silently evaluated on a different layout.
"""

from __future__ import annotations

import io
from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd

from c2_analyzer.classifiers.dom_baseline.common import (
    MODEL_NAMES,
    BaselineConfig,
    model_dir,
    readable_name,
    report_dir,
)
from c2_analyzer.classifiers.dom_baseline.data import DomDataset, label_mapping
from c2_analyzer.classifiers.dom_baseline.evaluate import (
    SCALAR_METRICS,
    compute_metrics,
    confusion_text,
    misclassified,
    per_language,
    plot_confusion_matrix,
)
from c2_analyzer.classifiers.dom_baseline.importance import compute_importance
from c2_analyzer.classifiers.dom_baseline.predict import best_model
from c2_analyzer.dataset.manifest import git_commit
from c2_analyzer.utils.io import atomic_write_text, write_json

SELECTION = "mean macro-F1 over grouped stratified CV folds on train+val (test never used)"
MISCLASSIFIED_COLUMNS = [
    "model",
    "sample_id",
    "language",
    "true",
    "predicted",
    "top_probability",
    "true_probability",
]


class StaleModelError(RuntimeError):
    """A saved model does not match the current split / features (retrain it)."""


def check_bundles(bundles: dict[str, dict[str, Any]], dataset: DomDataset) -> None:
    for name, bundle in bundles.items():
        problems = []
        if bundle["split_fingerprint"] != dataset.split_info.get("split_fingerprint"):
            problems.append("another split")
        if bundle["features"] != dataset.features:
            problems.append("another feature list")
        if bundle["labels"] != dataset.labels:
            problems.append("other classes")
        if bundle["dictionary_hash"] != dataset.dictionary_hash:
            problems.append("another feature dictionary")
        if problems:
            raise StaleModelError(
                f"{name} was trained on {', '.join(problems)} - run: python "
                f"scripts/train_dom_baseline.py train --version {dataset.version}"
            )


def _proba(bundle: dict[str, Any], X: np.ndarray, n_classes: int) -> np.ndarray:
    raw = bundle["estimator"].predict_proba(X)
    proba = np.zeros((len(X), n_classes))
    for column, cls in enumerate(bundle["estimator"].classes_):
        proba[:, int(cls)] = raw[:, column]
    return proba


def evaluate_version(
    dataset: DomDataset,
    bundles: dict[str, dict[str, Any]],
    config: BaselineConfig,
    figures: bool = True,
) -> tuple[dict[str, Any], list[dict]]:
    """(results dict, misclassified rows) - the ONE evaluation on the test split."""
    if not bundles:
        raise FileNotFoundError(
            f"no trained models for {dataset.version} - run: python "
            f"scripts/train_dom_baseline.py train --version {dataset.version}"
        )
    check_bundles(bundles, dataset)
    folder = report_dir(config, dataset.version) / "figures"
    test = dataset.rows("test").reset_index(drop=True)
    X_test, y_test = dataset.X("test"), dataset.y("test")
    labels = dataset.labels

    models, wrong = {}, []
    for name in MODEL_NAMES:
        if name not in bundles:
            continue
        bundle = bundles[name]
        proba = _proba(bundle, X_test, len(labels))
        predicted = proba.argmax(axis=1)
        metrics = compute_metrics(y_test, predicted, proba, labels)
        errors = misclassified(test, predicted, proba, labels, name)
        wrong.extend(errors)
        benign = labels.index("benign") if "benign" in labels else None
        flagged = (
            test.loc[(y_test == benign) & (predicted != benign), "sample_id"].tolist()
            if benign is not None
            else []
        )
        models[name] = {
            "display_name": bundle["display_name"],
            "params": bundle["params"],
            "grid": bundle["grid"],
            "cv": {"mean": bundle["cv"]["mean"], "std": bundle["cv"]["std"]},
            "cv_folds": [
                {key: fold[key] for key in SCALAR_METRICS} for fold in bundle["cv"]["folds"]
            ],
            "test": metrics,
            "benign_false_positives": flagged,
            "per_language": per_language(test, predicted, labels, config.min_language_support),
            "misclassified": len(errors),
            "training_seconds": bundle.get("training_seconds"),
        }
        if figures:
            plot_confusion_matrix(
                metrics["confusion_matrix"],
                labels,
                f"{bundle['display_name']} - test confusion matrix ({dataset.version})",
                folder / f"confusion_{name}.png",
            )
    info = dataset.split_info
    best = best_model(bundles)
    results = {
        "version": dataset.version,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "pilot": dataset.pilot,
        "classes": labels,
        "excluded_classes": info.get("excluded_classes", {}),
        "feature_set_version": dataset.feature_set_version,
        "dictionary_hash": dataset.dictionary_hash,
        "split": {
            key: info.get(key)
            for key in (
                "seed",
                "target_ratios",
                "actual_ratios",
                "max_ratio_difference",
                "counts",
                "counts_per_label",
                "counts_per_language",
                "language_placement",
                "clusters_in_two_splits",
                "cv_folds",
                "split_fingerprint",
            )
        },
        "manifest_fingerprint": info.get("manifest", {}).get("fingerprint"),
        "features": {
            "total": len(dataset.all_features),
            "used": len(dataset.features),
            "list": dataset.features,
            "dropped": dataset.dropped,
        },
        "selection": SELECTION,
        "best_model": best,
        "benign_fpr_target": config.benign_fpr_target,
        "models": models,
        "misclassified_total": len(wrong),
    }
    return results, wrong


def run_report(
    dataset: DomDataset,
    bundles: dict[str, dict[str, Any]],
    config: BaselineConfig,
    figures: bool = True,
) -> dict[str, Any]:
    """Evaluate + importance + write all report files and the model card. Returns results."""
    results, wrong = evaluate_version(dataset, bundles, config, figures)
    folder = report_dir(config, dataset.version)
    results["importance"] = compute_importance(
        bundles,
        dataset.X("test"),
        dataset.y("test"),
        config,
        folder / "figures" if figures else None,
    )
    write_json(results, folder / "results.json")
    atomic_write_text(render_markdown(results), folder / "results.md")
    _write_csv(pd.DataFrame(wrong, columns=MISCLASSIFIED_COLUMNS), folder / "misclassified.csv")
    _write_csv(
        pd.DataFrame(dataset.dropped, columns=["feature", "reason", "detail"]),
        folder / "dropped_features.csv",
    )
    write_json(
        model_card(results, dataset, bundles),
        model_dir(config, dataset.version) / "model_card.json",
    )
    return results


def _write_csv(frame: pd.DataFrame, path) -> None:
    buffer = io.StringIO()
    frame.to_csv(buffer, index=False, lineterminator="\n")
    atomic_write_text(buffer.getvalue(), path)


def model_card(results: dict, dataset: DomDataset, bundles: dict[str, dict[str, Any]]) -> dict:
    """model_card.json: enough to know exactly what each saved model is and how good it is."""
    first = next(iter(bundles.values()))
    return {
        "name": "C2 DOM baseline (Baseline 1: DOM-only structural classification)",
        "created_at": results["created_at"],
        "dataset_version": dataset.version,
        "manifest_fingerprint": results["manifest_fingerprint"],
        "split_fingerprint": dataset.split_info.get("split_fingerprint"),
        "feature_set_version": dataset.feature_set_version,
        "dictionary_hash": dataset.dictionary_hash,
        "pilot": dataset.pilot,
        "excluded_classes": results["excluded_classes"],
        "label_mapping": label_mapping(dataset.labels, results["excluded_classes"]),
        "final_features": dataset.features,
        "dropped_features": dataset.dropped,
        "selection": SELECTION,
        "best_model": results["best_model"],
        "seed": first["seed"],
        "models": {
            name: {
                "file": f"{name}.joblib",
                "display_name": bundles[name]["display_name"],
                "best_params": bundles[name]["params"],
                "trained_on": bundles[name]["trained_on"],
                "n_train": bundles[name]["n_train"],
                "trained_at": bundles[name]["trained_at"],
                "cv_mean": {
                    key: results["models"][name]["cv"]["mean"][key] for key in SCALAR_METRICS
                },
                "cv_std": {
                    key: results["models"][name]["cv"]["std"][key] for key in SCALAR_METRICS
                },
                "test": {key: results["models"][name]["test"][key] for key in SCALAR_METRICS},
            }
            for name in bundles
        },
        "library_versions": first["library_versions"],
        "git_commit": git_commit(),
        "intended_use": "Baseline for the ablation study (DOM-only vs NLP-only, behavior-only, "
        "fused). Research use on the C2 dataset; not a production detector.",
        "limitations": (
            "PILOT: trained on "
            + ", ".join(dataset.labels)
            + " only; excluded classes cannot be predicted. Small dataset with mostly "
            "unverified labels - test metrics have wide uncertainty."
            if dataset.pilot
            else "Small dataset - test metrics have wide uncertainty."
        ),
    }


# ---- markdown --------------------------------------------------------------------------------


def _pct(value: float | None, digits: int = 1) -> str:
    return "—" if value is None else f"{100 * value:.{digits}f} %"


def _num(value: float | None) -> str:
    return "—" if value is None else f"{value:.3f}"


def _pm(mean: float | None, std: float | None) -> str:
    return "—" if mean is None else f"{mean:.3f} ± {std:.3f}"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return lines


def render_markdown(results: dict) -> str:
    version, labels, models = results["version"], results["classes"], results["models"]
    split = results["split"]
    best = results["best_model"]
    lines = [f"# DOM baseline (Baseline 1) - {version}", ""]
    if results["pilot"]:
        excluded = ", ".join(f"{k} ({v})" for k, v in results["excluded_classes"].items())
        lines += [
            f"> **PILOT run.** {len(labels)} classes ({', '.join(labels)}); excluded because "
            f"they have too few pages: {excluded}. Labels of {version} are mostly unverified. "
            "Re-run unchanged on the next dataset version with "
            f"`python scripts/train_dom_baseline.py all --version <version>`.",
            "",
        ]
    lines += [
        f"Created {results['created_at']} · feature set `{results['feature_set_version']}` · "
        f"model selection: {results['selection']}.",
        "",
        "## Baseline 1 - DOM-only structural classification",
        "",
    ]
    rows = []
    for name, model in models.items():
        cv, test = model["cv"], model["test"]
        rows.append(
            [
                f"**{model['display_name']}**" if name == best else model["display_name"],
                _pm(cv["mean"]["macro_f1"], cv["std"]["macro_f1"]),
                _num(test["macro_f1"]),
                _num(test["weighted_f1"]),
                _num(test["accuracy"]),
                _num(test["balanced_accuracy"]),
                _num(test["roc_auc_ovr_macro"]),
                _pct(test["benign_fpr"]),
            ]
        )
    lines += _table(
        [
            "Model",
            "CV macro-F1 (mean ± std)",
            "Test macro-F1",
            "Test weighted-F1",
            "Test accuracy",
            "Test balanced acc.",
            "Test ROC-AUC (OvR macro)",
            "Benign FPR (test)",
        ],
        rows,
    )
    test_n = split["counts"]["test"]
    lines += [
        "",
        "Best model (by CV macro-F1, chosen before looking at test): "
        f"**{models[best]['display_name']}**. "
        f"Test split: {test_n} pages, evaluated once. Benign FPR target: ≤ "
        f"{_pct(results['benign_fpr_target'], 0)} (benign test pages predicted as any threat).",
        "",
        "CV details (mean ± std over folds):",
        "",
    ]
    cv_rows = []
    for model in models.values():
        mean, std = model["cv"]["mean"], model["cv"]["std"]
        cv_rows.append(
            [model["display_name"]]
            + [
                _pm(mean[k], std[k])
                for k in ("weighted_f1", "accuracy", "balanced_accuracy", "roc_auc_ovr_macro")
            ]
            + [_pm(mean.get(f"f1_{label}"), std.get(f"f1_{label}")) for label in labels]
        )
    lines += _table(
        ["Model", "weighted-F1", "accuracy", "balanced acc.", "ROC-AUC"]
        + [f"F1 {label}" for label in labels],
        cv_rows,
    )

    # ---- split
    lines += ["", "## Split", ""]
    split_rows = []
    for part in ("train", "val", "test"):
        per_label = split["counts_per_label"].get(part, {})
        split_rows.append(
            [part, split["counts"][part], _pct(split["actual_ratios"][part])]
            + [per_label.get(label, 0) for label in labels]
        )
    lines += _table(["split", "pages", "share"] + labels, split_rows)
    placement = ", ".join(
        f"{language}: " + " / ".join(f"{part} {n}" for part, n in parts.items())
        for language, parts in split["language_placement"].items()
    )
    lines += [
        "",
        f"Target 70/15/15, largest deviation {_pct(split['max_ratio_difference'], 2)}. Stratified "
        f"by label × language, grouped by near-duplicate cluster "
        f"({split['clusters_in_two_splits']} clusters in two splits). Seed {split['seed']}, "
        f"{split['cv_folds']} grouped CV folds over train+val. "
        f"Sinhala/Tamil placement: {placement}.",
        "",
        f"Split fingerprint `{split['split_fingerprint'][:16]}…` (shared by every later part).",
    ]

    # ---- features
    features = results["features"]
    lines += [
        "",
        "## Features",
        "",
        f"{features['total']} dictionary features → **{features['used']} used**. "
        "Dropped (decided on the TRAIN split only):",
        "",
    ]
    lines += (
        _table(
            ["feature", "reason", "detail"],
            [[f"`{d['feature']}`", d["reason"], d["detail"]] for d in features["dropped"]],
        )
        if features["dropped"]
        else ["None."]
    )

    # ---- per class / confusion / FPR
    lines += ["", "## Per-class test results", ""]
    for model in models.values():
        lines += [f"**{model['display_name']}**", ""]
        lines += _table(
            ["class", "precision", "recall", "F1", "support"],
            [
                [label, _num(v["precision"]), _num(v["recall"]), _num(v["f1"]), v["support"]]
                for label, v in model["test"]["per_class"].items()
            ],
        )
        lines.append("")
    lines += [
        f"## Confusion matrix - {models[best]['display_name']} (test)",
        "",
        "```",
        confusion_text(models[best]["test"]["confusion_matrix"], labels),
        "```",
        "",
        "Figures: " + ", ".join(f"`figures/confusion_{name}.png`" for name in models),
        "",
        "## Benign false positives (test)",
        "",
    ]
    for model in models.values():
        flagged = model["benign_false_positives"]
        lines.append(
            f"- {model['display_name']}: {_pct(model['test']['benign_fpr'])}"
            + (f" - {', '.join(flagged)}" if flagged else " - none")
        )

    lines += ["", f"## Per language - {models[best]['display_name']} (test)", ""]
    lines += _table(
        [
            "language",
            "pages",
            "accuracy",
            "macro-F1 (classes present)",
            "benign FPR",
            "classes",
            "note",
        ],
        [
            [
                language,
                v["n"],
                _num(v["accuracy"]),
                _num(v["macro_f1"]),
                _pct(v["benign_fpr"]),
                ", ".join(f"{k} {n}" for k, n in v["labels"].items()),
                "small n - anecdotal" if v["small_n"] else "",
            ]
            for language, v in models[best]["per_language"].items()
        ],
    )

    # ---- importance
    importance = results.get("importance") or {}
    lines += ["", "## Feature importance", "", f"> {importance.get('caveat', '')}", ""]
    if "xgboost" in importance:
        lines += ["**XGBoost - global SHAP (mean |SHAP| on test, all classes)**", ""]
        lines += _table(
            ["#", "feature", "mean |SHAP|"] + labels,
            [
                [i + 1, row["name"], _num(row["value"])]
                + [_num(row["per_class"][label]) for label in labels]
                for i, row in enumerate(importance["xgboost"]["shap_global"])
            ],
        )
        lines += ["", "**XGBoost - gain**", ""]
        lines += _ranked(importance["xgboost"]["gain"])
    if "random_forest" in importance:
        lines += ["", "**Random Forest - permutation importance on test (macro-F1 drop)**", ""]
        lines += _table(
            ["#", "feature", "drop", "std"],
            [
                [i + 1, row["name"], _num(row["value"]), _num(row["std"])]
                for i, row in enumerate(importance["random_forest"]["permutation_test"])
            ],
        )
        lines += ["", "**Random Forest - impurity importance**", ""]
        lines += _ranked(importance["random_forest"]["impurity"])
    if "logreg" in importance:
        lines += ["", "**Logistic Regression - standardized coefficients (top 5 per class)**", ""]
        rows = []
        for label, top in importance["logreg"]["standardized_coefficients"].items():
            rows += [[label, row["name"], f"{row['value']:+.3f}"] for row in top[:5]]
        lines += _table(["class", "feature", "coefficient"], rows)
    lines += [
        "",
        "Figures: `figures/importance_*.png`, `figures/shap_global_xgboost.png`, "
        "`figures/shap_beeswarm_<class>.png`.",
        "",
        "## Misclassified test pages",
        "",
    ]
    lines += [
        f"- {model['display_name']}: {model['misclassified']} of {test_n}"
        for model in models.values()
    ]
    lines += [
        "",
        "`misclassified.csv` lists them (sample_id, true, predicted, probabilities). In the "
        "inspector tick **misclassified (test)** to browse them.",
        "",
        "## Chosen hyperparameters",
        "",
    ]
    for model in models.values():
        params = ", ".join(f"{k}={v}" for k, v in model["params"].items())
        lines.append(f"- {model['display_name']}: {params} ({len(model['grid'])} grid points)")
    lines += [
        "",
        "## Reproduce",
        "",
        "```bash",
        f"python scripts/train_dom_baseline.py all --version {version}",
        "```",
        "",
    ]
    return "\n".join(lines)


def _ranked(rows: list[dict]) -> list[str]:
    return _table(
        ["#", "feature", "value"],
        [[i + 1, row["name"], _num(row["value"])] for i, row in enumerate(rows)],
    )


def shap_top_text(results: dict, n: int = 10) -> list[str]:
    """'1. <readable name>  0.123' lines of the global SHAP ranking (for the CLI)."""
    rows = (results.get("importance") or {}).get("xgboost", {}).get("shap_global", [])
    return [
        f"{i + 1:2d}. {readable_name(row['feature'])}  {row['value']:.3f}"
        for i, row in enumerate(rows[:n])
    ]
