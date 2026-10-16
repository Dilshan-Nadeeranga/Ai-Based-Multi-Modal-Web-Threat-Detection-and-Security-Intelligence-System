"""TF-IDF (character 2-5-grams) + Logistic Regression text baseline.

Part 6: XLM-R content classification (6A, page level) - the honest comparison.

Why this baseline exists (viva): a 278M-parameter transformer is only worth its cost
if it beats a cheap model on the SAME pages. Character n-grams inside word
boundaries (``char_wb``) need no tokenizer or language model, so they work for
English, Sinhala, Tamil and every "other" script alike, and they capture brand
names, "verify", "wallet", ".exe" and the like. If XLM-R does not clearly beat this,
the text signal - not the model - is the limit.

Protocol = Part 4's (so the ablation rows are comparable): input = the same Part 5A
page_text examples (``nlp/dataset.py``); C chosen by mean macro-F1 over the SHARED
grouped CV folds (``data/splits/<v>/cv_folds.csv``, train+val; the vectorizer is fit
inside each fold, so no fold sees its own vocabulary); refit on train+val; test
evaluated ONCE.

Outputs: ``models/text_baseline/<v>/{tfidf_logreg.joblib, model_card.json,
label_mapping.json}``, ``reports/text_baseline/<v>/{results.json, results.md,
misclassified.csv, figures/confusion_tfidf_logreg.png}``.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from c2_analyzer.classifiers.dom_baseline.common import library_versions
from c2_analyzer.classifiers.dom_baseline.data import DatasetError
from c2_analyzer.classifiers.dom_baseline.evaluate import plot_confusion_matrix
from c2_analyzer.dataset.manifest import git_commit
from c2_analyzer.dataset.splits import load_cv_folds
from c2_analyzer.nlp.common import BASELINE_DISPLAY, BASELINE_NAME, XlmrConfig
from c2_analyzer.nlp.dataset import TextExamples, build_examples
from c2_analyzer.nlp.metrics import full_metrics, misclassified_rows, per_language, seed_summary
from c2_analyzer.nlp.report import render_results_md, write_csv
from c2_analyzer.utils.io import atomic_write_text, write_json

SELECTION = "C by mean macro-F1 over the shared grouped CV folds (train+val); test never used"


def make_pipeline(settings: dict, C: float, seed: int = 42) -> Pipeline:  # noqa: N803
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer=settings["analyzer"],
                    ngram_range=tuple(settings["ngram_range"]),
                    min_df=int(settings["min_df"]),
                    max_features=int(settings["max_features"]),
                    sublinear_tf=bool(settings["sublinear_tf"]),
                    lowercase=True,
                ),
            ),
            (
                "logreg",
                LogisticRegression(
                    C=float(C),
                    class_weight="balanced",
                    max_iter=int(settings["max_iter"]),
                    random_state=seed,
                ),
            ),
        ]
    )


def predict_proba(pipeline: Pipeline, texts: list[str], n_classes: int) -> np.ndarray:
    """Probabilities for ALL classes (a class missing from a fold's train gets 0)."""
    proba = pipeline.predict_proba(list(texts))
    full = np.zeros((len(texts), n_classes))
    full[:, pipeline.classes_.astype(int)] = proba
    return full


def top_ngrams(pipeline: Pipeline, labels: list[str], n: int = 10) -> dict[str, list[str]]:
    """Strongest positive n-grams per class (LR coefficients) - what the model reads."""
    names = pipeline.named_steps["tfidf"].get_feature_names_out()
    coef = pipeline.named_steps["logreg"].coef_
    classes = pipeline.named_steps["logreg"].classes_.astype(int)
    if coef.shape[0] == 1:  # binary: one row for the positive class
        coef = np.vstack([-coef[0], coef[0]])
    return {
        labels[c]: [str(names[j]) for j in np.argsort(-coef[row])[:n]]
        for row, c in enumerate(classes)
    }


def train_text_baseline(
    version: str,
    config: XlmrConfig | None = None,
    data: TextExamples | None = None,
    splits_root: Path | None = None,
    models_dir: Path | None = None,
    reports_dir: Path | None = None,
    figures: bool = True,
    log=print,
) -> dict:
    """CV-tune C, refit on train+val, evaluate test once, write models + reports."""
    config = config or XlmrConfig.load()
    settings = config.baseline
    data = data or build_examples(version, splits_root=splits_root)
    labels = data.labels
    folds = load_cv_folds(version, splits_root).set_index("sample_id")["fold"]
    pool, test = data.rows("train", "val"), data.rows("test")
    fold_of = np.array([folds.get(row["sample_id"], -1) for row in pool])
    if (fold_of < 0).any():
        raise DatasetError("cv_folds.csv does not cover every train+val page - re-run the split")
    texts = np.array([row["text"] for row in pool], dtype=object)
    y = np.array([row["label_id"] for row in pool])

    started = time.perf_counter()
    grid = []
    for C in settings["C"]:  # noqa: N806
        runs = []
        for fold in sorted(set(fold_of.tolist())):
            fit, held = fold_of != fold, fold_of == fold
            pipeline = make_pipeline(settings, C).fit(list(texts[fit]), y[fit])
            proba = predict_proba(pipeline, list(texts[held]), len(labels))
            runs.append(full_metrics(y[held], proba.argmax(axis=1), proba, labels))
        summary = seed_summary(runs)
        grid.append({"C": float(C), "summary": summary, "folds": runs})
        log(
            f"C={C:g}: CV macro-F1 {summary['mean']['macro_f1']:.3f} ± "
            f"{summary['std']['macro_f1']:.3f}"
        )
    best = max(grid, key=lambda g: (g["summary"]["mean"]["macro_f1"], -g["C"]))
    pipeline = make_pipeline(settings, best["C"]).fit(list(texts), y)
    seconds = time.perf_counter() - started

    # the ONE test evaluation
    test_proba = predict_proba(pipeline, [row["text"] for row in test], len(labels))
    y_test = np.array([row["label_id"] for row in test])
    predicted = test_proba.argmax(axis=1)
    metrics = full_metrics(y_test, predicted, test_proba, labels)
    benign = labels.index("benign") if "benign" in labels else None
    flagged = [
        row["sample_id"]
        for row, p in zip(test, predicted, strict=True)
        if benign is not None and row["label_id"] == benign and p != benign
    ]
    wrong = misclassified_rows(test, test_proba, labels, BASELINE_NAME)
    entry = {
        "display_name": BASELINE_DISPLAY,
        "params": {"C": best["C"], **{k: v for k, v in settings.items() if k != "C"}},
        "grid": {"C": [float(c) for c in settings["C"]]},
        "cv": {"mean": best["summary"]["mean"], "std": best["summary"]["std"]},
        "cv_grid": [
            {
                "C": g["C"],
                "mean_macro_f1": g["summary"]["mean"]["macro_f1"],
                "std_macro_f1": g["summary"]["std"]["macro_f1"],
            }
            for g in grid
        ],
        "test": metrics,
        "benign_false_positives": flagged,
        "per_language": per_language(
            y_test,
            predicted,
            [row["language"] for row in test],
            labels,
            config.languages,
            config.min_language_support,
        ),
        "misclassified": len(wrong),
        "training_seconds": round(seconds, 2),
        "vocabulary_size": len(pipeline.named_steps["tfidf"].vocabulary_),
        "top_ngrams": top_ngrams(pipeline, labels),
    }
    created = datetime.now().astimezone().isoformat(timespec="seconds")
    results = {
        "arm": "text (TF-IDF)",
        "version": version,
        "created_at": created,
        "classes": labels,
        "split": {
            "split_fingerprint": data.meta["split_fingerprint"],
            "counts": data.meta["counts"],
        },
        "manifest_fingerprint": data.meta["manifest_fingerprint"],
        "text_schema_version": data.meta["text_schema_version"],
        "text_rules_hash": data.meta["text_rules_hash"],
        "selection": SELECTION,
        "best_model": BASELINE_NAME,
        "models": {BASELINE_NAME: entry},
        "misclassified_total": len(wrong),
    }

    models_dir = models_dir or config.baseline_models_dir(version)
    reports_dir = reports_dir or config.baseline_reports_dir(version)
    versions = library_versions()
    Path(models_dir).mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": pipeline,
            "labels": labels,
            "params": entry["params"],
            "version": version,
            "split_fingerprint": data.meta["split_fingerprint"],
            "text_rules_hash": data.meta["text_rules_hash"],
            "trained_on": "train+val",
            "trained_at": created,
            "library_versions": versions,
        },
        Path(models_dir) / f"{BASELINE_NAME}.joblib",
    )
    write_json(data.label_mapping, Path(models_dir) / "label_mapping.json")
    write_json(
        {
            "name": "TF-IDF char_wb 2-5 + Logistic Regression (Part 6A text baseline)",
            "created_at": created,
            "dataset_version": version,
            "manifest_fingerprint": data.meta["manifest_fingerprint"],
            "split_fingerprint": data.meta["split_fingerprint"],
            "text_schema_version": data.meta["text_schema_version"],
            "text_rules_hash": data.meta["text_rules_hash"],
            "label_mapping": data.label_mapping,
            "selection": SELECTION,
            "params": entry["params"],
            "cv_mean": entry["cv"]["mean"],
            "cv_std": entry["cv"]["std"],
            "test": {k: metrics[k] for k in metrics if k not in ("per_class", "confusion_matrix")},
            "library_versions": versions,
            "git_commit": git_commit(),
        },
        Path(models_dir) / "model_card.json",
    )
    write_json(results, Path(reports_dir) / "results.json")
    atomic_write_text(render_results_md(results), Path(reports_dir) / "results.md")
    write_csv(pd.DataFrame(wrong), Path(reports_dir) / "misclassified.csv")
    if figures:
        plot_confusion_matrix(
            metrics["confusion_matrix"],
            labels,
            f"{BASELINE_DISPLAY} - test confusion matrix ({version})",
            Path(reports_dir) / "figures" / f"confusion_{BASELINE_NAME}.png",
        )
    return results
