"""The ablation study: single arms, pairs and the tri-modal fusion on the same pages.

Part 9: Tri-modal fusion + ablation study (Batch A, tasks 3-4) - the main thesis table.

Rows (whatever arms are available; a missing optional arm is reported, not faked):
    single  DOM-only, Behavior-only, Text TF-IDF, Text XLM-R (each arm's OOF / final probs)
    pairs   DOM+Behavior, DOM+Text, Behavior+Text - Text = every available text arm; each
            pair is fused with the 4 strategies and shown with the one CV picks
    tri     DOM+Behavior+Text with EACH strategy; the FINAL fusion model = the tri-modal
            strategy with the best CV macro-F1 (ties: the simpler one, mean < weighted <
            stacking < hybrid)

Protocol (viva - why the test split is used once): every number used to CHOOSE anything
(strategy weights, the LR, the final strategy, the benign threshold) comes from grouped CV
on train+val. The 68 test pages are predicted once per row, after all choices are made,
and only reported. Choosing by test would make the test score optimistic - with 68 pages
one lucky page is worth ~1.5 points of accuracy. The CV columns are the mean +/- std over
the 5 folds of the configuration that was selected (as in Parts 4, 6 and 8).

Per row: CV macro-F1, test macro-F1 with a paired-bootstrap 95 % CI, weighted-F1,
accuracy, ROC-AUC, benign FPR at argmax and at the <= 2 % OOF threshold (+ recall cost),
per-class F1, per-language accuracy (n). Then: tri-modal vs best single arm (bootstrap CI
of the difference), complementarity buckets, explanations (weights / LR coefficients /
SHAP), figures, and the saved final model + model card.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from c2_analyzer.classifiers.dom_baseline.common import BaselineConfig, library_versions
from c2_analyzer.classifiers.dom_baseline.data import label_mapping
from c2_analyzer.classifiers.dom_baseline.evaluate import summarize_folds
from c2_analyzer.dataset.manifest import git_commit
from c2_analyzer.fusion import bootstrap
from c2_analyzer.fusion.common import STRATEGY_ORDER, FusionConfig
from c2_analyzer.fusion.complementarity import complementarity
from c2_analyzer.fusion.data import FusionData
from c2_analyzer.fusion.explain import global_explanation
from c2_analyzer.fusion.model import save_bundle, to_bundle
from c2_analyzer.fusion.operating_point import choose_threshold, evaluate_operating_point
from c2_analyzer.fusion.strategies import ArmOnly, cross_validate, make_strategy
from c2_analyzer.nlp.metrics import full_metrics, per_language
from c2_analyzer.utils.io import write_json

LANGUAGES = ["en", "si", "ta", "mixed", "other"]
MIN_LANGUAGE_SUPPORT = 10
SCALARS = (
    "macro_f1",
    "weighted_f1",
    "accuracy",
    "balanced_accuracy",
    "roc_auc_ovr_macro",
    "benign_fpr",
    "macro_precision",
    "macro_recall",
)


@dataclass
class RowSpec:
    key: str  # "dom", "dom+behavior", "tri"
    title: str  # "DOM-only", "DOM+Behavior", "DOM+Behavior+Text"
    group: str  # single / pair / tri
    arms: list[str]


def row_specs(available: list[str], config: FusionConfig) -> list[RowSpec]:
    """The rows of the ablation for the arms that are available."""
    specs = [RowSpec(arm, config.arm_display(arm), "single", [arm]) for arm in available]
    text = [arm for arm in available if config.is_text(arm)]
    text_title = "Text" + (
        " (" + " + ".join(config.arm_display(a).replace("Text ", "") for a in text) + ")"
        if text
        else ""
    )
    dom, behavior = "dom" in available, "behavior" in available
    if dom and behavior:
        specs.append(RowSpec("dom+behavior", "DOM+Behavior", "pair", ["dom", "behavior"]))
    if dom and text:
        specs.append(RowSpec("dom+text", f"DOM+{text_title}", "pair", ["dom", *text]))
    if behavior and text:
        specs.append(
            RowSpec("behavior+text", f"Behavior+{text_title}", "pair", ["behavior", *text])
        )
    if dom and behavior and text:
        specs.append(
            RowSpec("tri", f"DOM+Behavior+{text_title}", "tri", ["dom", "behavior", *text])
        )
    return specs


def _strategies(spec: RowSpec, config: FusionConfig) -> list[str]:
    if spec.group == "single":
        return ["single"]
    names = [name for name in STRATEGY_ORDER if name in config.raw["strategies"]]
    if not any(not config.is_text(arm) for arm in spec.arms):
        names = [name for name in names if name != "hybrid"]  # hybrid needs a feature arm
    return names


def evaluate_row(data: FusionData, spec: RowSpec, strategy: str, correlation: float) -> dict:
    """CV on train+val, fit on train+val, ONE test prediction, threshold, per language."""
    config, labels = data.config, data.labels
    pool_ids, test_ids = data.ids("pool"), data.ids("test")
    pool, test = data.inputs(spec.arms, pool_ids), data.inputs(spec.arms, test_ids)
    y_pool, y_test, folds = data.y("pool"), data.y("test"), data.folds()

    def make():
        if strategy == "single":
            return ArmOnly(spec.arms[0])
        return make_strategy(strategy, config, config.seed, correlation)

    fold_metrics, oof_fused = cross_validate(make, pool, y_pool, folds)
    model = make().fit(pool, y_pool, folds)
    test_proba = model.predict_proba(test)  # the one test prediction of this row
    predicted = test_proba.argmax(axis=1)
    metrics = full_metrics(y_test, predicted, test_proba, labels)
    benign = labels.index("benign")
    threshold = choose_threshold(y_pool, oof_fused, benign, config.benign_fpr_target)
    operating = evaluate_operating_point(y_test, test_proba, labels, benign, threshold["threshold"])
    return {
        "key": spec.key if strategy in ("single",) else f"{spec.key}:{strategy}",
        "row": spec.key,
        "title": spec.title,
        "group": spec.group,
        "arms": spec.arms,
        "strategy": strategy,
        "strategy_display": (
            "single arm" if strategy == "single" else config.strategy_display(strategy)
        ),
        "params": model.params(),
        "cv": summarize_folds(fold_metrics),
        "cv_folds_macro_f1": [fold["macro_f1"] for fold in fold_metrics],
        "test": metrics,
        "per_language": per_language(
            y_test, predicted, data.language_of(test_ids), labels, LANGUAGES, MIN_LANGUAGE_SUPPORT
        ),
        "operating_point": {
            **threshold,
            "test": {key: operating[key] for key in ("argmax", "fpr_constrained")},
        },
        "_model": model,
        "_test_proba": test_proba,
        "_test_pred": predicted,
        "_test_pred_threshold": np.asarray(operating["predicted"]),
    }


def _cv_key(entry: dict) -> tuple:
    order = list(STRATEGY_ORDER)
    rank = order.index(entry["strategy"]) if entry["strategy"] in order else -1
    return (round(entry["cv"]["mean"]["macro_f1"], 10), -rank)


def _public(entry: dict) -> dict:
    return {key: value for key, value in entry.items() if not key.startswith("_")}


def run_ablation(
    version: str,
    config: FusionConfig | None = None,
    data: FusionData | None = None,
    figures: bool = True,
    save: bool = True,
    log=print,
) -> dict:
    """Run the whole study; writes reports/ablation/<v>/ and models/fusion/<v>/."""
    from c2_analyzer.fusion import report

    config = config or FusionConfig.load()
    data = data or FusionData.load(version, config)
    if not data.oofs:
        raise FileNotFoundError(f"no OOF predictions for {version} - run run_ablation.py")
    if data.missing:
        log(f"arms without OOF predictions (left out): {', '.join(data.missing)}")
    correlation = BaselineConfig.load().correlation_threshold
    labels, test_ids = data.labels, data.ids("test")
    y_test = data.y("test")

    entries = []
    for spec in row_specs(data.available, config):
        for strategy in _strategies(spec, config):
            entry = evaluate_row(data, spec, strategy, correlation)
            log(
                f"{entry['title']:<42} {entry['strategy_display']:<26} CV "
                f"{entry['cv']['mean']['macro_f1']:.3f} ± {entry['cv']['std']['macro_f1']:.3f}"
            )
            entries.append(entry)

    # choices - all by CV, never by test
    for row in {e["row"] for e in entries if e["group"] != "single"}:
        candidates = [e for e in entries if e["row"] == row]
        best = max(candidates, key=_cv_key)
        for e in candidates:
            e["selected_for_row"] = e is best
    singles = [e for e in entries if e["group"] == "single"]
    for e in singles:
        e["selected_for_row"] = True
    top_group = "tri" if any(e["group"] == "tri" for e in entries) else "pair"
    fused = [e for e in entries if e["group"] == top_group]
    final = max(fused, key=_cv_key) if fused else max(singles, key=_cv_key)
    best_single_cv = max(singles, key=_cv_key)
    best_single_test = max(singles, key=lambda e: e["test"]["macro_f1"])

    # paired bootstrap on the same resamples for every row
    settings = config.bootstrap
    indices = bootstrap.resample_indices(
        len(y_test), int(settings["n_resamples"]), int(settings["seed"])
    )
    confidence = float(settings["confidence"])
    for e in entries:
        scores = bootstrap.bootstrap_scores(y_test, e["_test_pred"], indices)
        e["bootstrap"] = bootstrap.summarize(e["test"]["macro_f1"], scores, confidence)
    comparison = {
        "final": final["key"],
        "vs_best_single_by_cv": {
            "single": best_single_cv["key"],
            **bootstrap.paired_difference(
                y_test, final["_test_pred"], best_single_cv["_test_pred"], indices, confidence
            ),
        },
        "vs_best_single_on_test": {
            "single": best_single_test["key"],
            **bootstrap.paired_difference(
                y_test, final["_test_pred"], best_single_test["_test_pred"], indices, confidence
            ),
        },
    }

    # complementarity (text = the best text arm by CV)
    by_key = {e["key"]: e for e in entries}
    modality_preds = {}
    for modality, arms in (("dom", ["dom"]), ("behavior", ["behavior"])):
        if arms[0] in by_key:
            modality_preds[modality] = by_key[arms[0]]["_test_pred"]
    text_singles = [e for e in singles if config.is_text(e["arms"][0])]
    text_arm = max(text_singles, key=_cv_key)["key"] if text_singles else None
    if text_arm:
        modality_preds["text"] = by_key[text_arm]["_test_pred"]
    comp = complementarity(
        test_ids, y_test, modality_preds, final["_test_pred"], config.examples_per_bucket
    )
    comp["text_arm"] = text_arm

    # explanations of the tri-modal stacker / hybrid (+ the final model)
    explanations = {}
    for e in entries:
        if e["group"] == top_group and e["strategy"] in ("weighted", "stacking", "hybrid"):
            inputs = data.inputs(e["arms"], test_ids)
            explanations[e["strategy"]] = global_explanation(
                e["_model"], inputs, config.top_features
            )
    if final["strategy"] not in explanations and final["strategy"] != "single":
        explanations[final["strategy"]] = global_explanation(
            final["_model"], data.inputs(final["arms"], test_ids), config.top_features
        )

    created = datetime.now().astimezone().isoformat(timespec="seconds")
    results = {
        "version": version,
        "created_at": created,
        "classes": labels,
        "split": {
            "split_fingerprint": data.ref.split_fingerprint,
            "cv_folds_fingerprint": data.ref.folds_fingerprint,
            "counts": {
                "train+val": len(data.ids("pool")),
                "test": len(test_ids),
            },
        },
        "arms_available": data.available,
        "arms_missing": data.missing,
        "arm_models": {arm: oof.manifest for arm, oof in data.oofs.items()},
        "benign_fpr_target": config.benign_fpr_target,
        "bootstrap_settings": settings,
        "entries": [_public(e) for e in entries],
        "final": _public(final),
        "best_single_by_cv": best_single_cv["key"],
        "best_single_on_test": best_single_test["key"],
        "comparison": comparison,
        "complementarity": comp,
        "explanations": explanations,
    }
    reports_dir = config.reports_dir(version)
    if save:
        report.write_reports(results, entries, data, reports_dir, figures=figures)
        save_final(final, results, data, config.models_dir(version))
        log(f"reports: {reports_dir}")
        log(f"model:   {config.models_dir(version)}")
    return results


def save_final(final: dict, results: dict, data: FusionData, folder: Path) -> None:
    """models/fusion/<v>/{fusion.joblib, model_card.json, label_mapping.json}."""
    if final["strategy"] == "single":
        return
    labels = data.labels
    threshold = {
        key: final["operating_point"][key]
        for key in ("threshold", "target", "oof_benign_fpr", "oof_threat_recall")
    }
    versions = library_versions()
    bundle = to_bundle(
        final["_model"],
        labels,
        [arm for arm in final["arms"] if data.config.is_text(arm)],
        version=data.ref.version,
        split_fingerprint=data.ref.split_fingerprint,
        cv_folds_fingerprint=data.ref.folds_fingerprint,
        threshold=threshold,
        cv=final["cv"],
        trained_on="train+val (arm OOF probabilities)",
        trained_at=results["created_at"],
        library_versions=versions,
    )
    save_bundle(bundle, folder)
    excluded = data.ref.excluded_classes
    write_json(label_mapping(labels, excluded), Path(folder) / "label_mapping.json")
    arm_versions = {
        arm: {
            key: oof.manifest.get(key)
            for key in (
                "part",
                "model",
                "model_display",
                "params",
                "model_trained_at",
                "feature_set_version",
                "dictionary_hash",
                "text_rules_hash",
                "seed",
                "base_model",
            )
            if oof.manifest.get(key) is not None
        }
        for arm, oof in data.oofs.items()
        if arm in final["arms"]
    }
    card = {
        "name": "C2 tri-modal fusion model (Part 9A)",
        "created_at": results["created_at"],
        "dataset_version": data.ref.version,
        "split_fingerprint": data.ref.split_fingerprint,
        "cv_folds_fingerprint": data.ref.folds_fingerprint,
        "strategy": final["strategy"],
        "strategy_display": final["strategy_display"],
        "arms": final["arms"],
        "arms_missing": results["arms_missing"],
        "arm_models": arm_versions,
        "params": final["params"],
        "selection": "tri-modal strategy with the best mean grouped-CV macro-F1 on train+val "
        "(ties: the simpler strategy); test never used for any choice",
        "cv_mean": final["cv"]["mean"],
        "cv_std": final["cv"]["std"],
        "test": {key: final["test"].get(key) for key in SCALARS},
        "test_bootstrap_macro_f1": final["bootstrap"],
        "benign_threshold": {
            **threshold,
            "rule": "benign if P(benign) >= threshold, else the most probable threat class",
            "test": {
                key: value
                for key, value in final["operating_point"]["test"]["fpr_constrained"].items()
                if key != "confusion_matrix"
            },
        },
        "label_mapping": label_mapping(labels, excluded),
        "library_versions": versions,
        "git_commit": git_commit(),
        "intended_use": "Research: the fused arm of C2's ablation study. The public /analyze "
        "API (Part 9 Batch B) will use it; not yet a production detector.",
        "limitations": "68 test pages (wide CIs); arm OOF probabilities of the fusion's "
        "training folds come from arm models that saw the fusion's held-out fold (standard "
        "stacking, not fully nested); mostly English pages.",
    }
    write_json(card, Path(folder) / "model_card.json")


def test_predictions_frame(entries: list[dict], data: FusionData, final: dict) -> pd.DataFrame:
    """One row per test page: true label, language, every row's prediction."""
    labels, test_ids = data.labels, data.ids("test")
    frame = pd.DataFrame(
        {
            "sample_id": test_ids,
            "language": data.language_of(test_ids),
            "true": [labels[i] for i in data.y("test")],
        }
    )
    for e in entries:
        if e.get("selected_for_row") or e["group"] == "tri":
            frame[e["key"]] = [labels[i] for i in e["_test_pred"]]
    frame[f"{final['key']}@fpr_threshold"] = [labels[i] for i in final["_test_pred_threshold"]]
    return frame
