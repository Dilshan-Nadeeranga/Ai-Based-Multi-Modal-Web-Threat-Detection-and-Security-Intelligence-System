"""Evaluate the fine-tuned XLM-R models once on val + test (tasks 8-12) + ablation table.

Part 6: XLM-R content classification (6A, page level).

For the final model and for each seed: per-class P / R / F1, macro P / R / F1
(PRIMARY: macro-F1), weighted-F1, accuracy, benign FPR, ROC-AUC OvR; per language
(en, si, ta, mixed, other - Part 5A detected, with n and a small-n warning; tasks
8-10); confusion matrices (counts + row-normalized PNG, task 12); misclassified.csv;
mean ± std over the seeds (task 11).

Where the probabilities come from:
- **final**: always recomputed HERE on the local CPU (the model the API serves), and
  compared with the Colab ``final/predictions.jsonl``. PASS = the predicted label is
  identical for EVERY page and max |Δp| < ``inference.prediction_tolerance`` (0.01).
  Exact equality is not expected: the Colab numbers come from a CUDA GPU (other
  kernels / summation order, fp16-trained weights read back), the local ones from a
  CPU in fp32, so differences of ~1e-3 are normal. A changed label or a |Δp| of 0.01+
  means a different library version or a broken download.
- **each seed**: local CPU if its weights were downloaded, else its Colab
  ``predictions.jsonl`` (by default only final/ is downloaded - 1.1 GB instead of 4.4).

Before anything is scored the models are checked against the CURRENT split and
label mapping (StaleModelError otherwise), like Part 4's ``check_bundles``.

Why test is used once (viva): the seed and every hyperparameter were chosen on val.
Looking at test while choosing would turn it into a second validation set and the
reported number would be optimistic. Re-running this script recomputes the same
numbers from the same saved models; it does not choose anything.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from c2_analyzer.classifiers.dom_baseline.evaluate import plot_confusion_matrix
from c2_analyzer.config import load_yaml_config, resolve_path
from c2_analyzer.nlp.common import XLMR_DISPLAY, XlmrConfig
from c2_analyzer.nlp.dataset import TextExamples, build_examples
from c2_analyzer.nlp.metrics import (
    TEXT_SCALARS,
    full_metrics,
    misclassified_rows,
    per_language,
    seed_summary,
)
from c2_analyzer.nlp.report import (
    ablation_rows,
    ablation_text,
    render_ablation_md,
    render_results_md,
    write_csv,
)
from c2_analyzer.nlp.train import LABEL_MAPPING_FILE, SELECTION_RULE, read_jsonl
from c2_analyzer.utils.io import atomic_write_text, write_json

WEIGHTS = "model.safetensors"


class StaleModelError(RuntimeError):
    """A saved model was trained on another split / label mapping: retrain, never score."""


def seed_dirs(model_root: Path) -> list[tuple[int, Path]]:
    found = []
    for path in Path(model_root).glob("seed_*"):
        if path.is_dir() and path.name[5:].isdigit():
            found.append((int(path.name[5:]), path))
    return sorted(found)


def check_model_dir(model_root: Path, data: TextExamples) -> None:
    """final/ and every seed must match the current split fingerprint and label mapping."""
    expected = data.label_mapping
    for folder in [Path(model_root) / "final"] + [p for _, p in seed_dirs(model_root)]:
        metrics_path, mapping_path = folder / "metrics.json", folder / LABEL_MAPPING_FILE
        if not metrics_path.is_file() or not mapping_path.is_file():
            raise StaleModelError(f"{folder} has no metrics.json / label_mapping.json")
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))
        if (
            mapping.get("classes") != expected["classes"]
            or mapping.get("index") != expected["index"]
        ):
            raise StaleModelError(
                f"{folder.name}: label mapping {mapping.get('classes')} != current "
                f"{expected['classes']} - retrain"
            )
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        if metrics.get("split_fingerprint") != data.meta["split_fingerprint"]:
            raise StaleModelError(
                f"{folder.name} was trained on another split (fingerprint "
                f"{str(metrics.get('split_fingerprint'))[:12]} != "
                f"{data.meta['split_fingerprint'][:12]}) - retrain"
            )


def _colab_predictions(folder: Path, rows: list[dict], n_classes: int) -> np.ndarray | None:
    path = Path(folder) / "predictions.jsonl"
    if not path.is_file():
        return None
    stored = {(r["split"], r["sample_id"]): r["probabilities"] for r in read_jsonl(path)}
    if any((row["split"], row["sample_id"]) not in stored for row in rows):
        return None
    proba = np.array([stored[(row["split"], row["sample_id"])] for row in rows], dtype=float)
    return proba if proba.shape[1] == n_classes else None


def local_predictions(folder: Path, rows: list[dict], config: XlmrConfig) -> np.ndarray:
    """Probabilities of a saved checkpoint on the local CPU (fp32)."""
    from c2_analyzer.nlp.model import load_classifier, predict_proba

    model, tokenizer = load_classifier(folder, device="cpu")
    max_length = int(json.loads((Path(folder) / "metrics.json").read_text())["max_length"])
    return predict_proba(
        model,
        tokenizer,
        [row["text"] for row in rows],
        max_length=max_length,
        batch_size=int(config.inference["batch_size"]),
        device="cpu",
    )


def _score(name: str, rows: list[dict], proba: np.ndarray, data: TextExamples, config):
    labels = data.labels
    entry, wrong = {}, []
    for split_name in ("val", "test"):
        index = [i for i, row in enumerate(rows) if row["split"] == split_name]
        part = [rows[i] for i in index]
        p = proba[index]
        y = np.array([row["label_id"] for row in part])
        predicted = p.argmax(axis=1)
        entry[split_name] = full_metrics(y, predicted, p, labels)
        entry.setdefault("per_language", {})[split_name] = per_language(
            y,
            predicted,
            [row["language"] for row in part],
            labels,
            config.languages,
            config.min_language_support,
        )
        if split_name == "test":
            benign = labels.index("benign") if "benign" in labels else None
            entry["benign_false_positives"] = [
                row["sample_id"]
                for row, pred in zip(part, predicted, strict=True)
                if benign is not None and row["label_id"] == benign and pred != benign
            ]
            wrong = misclassified_rows(part, p, labels, name)
            entry["misclassified"] = len(wrong)
    return entry, wrong


def consistency_check(colab: np.ndarray, local: np.ndarray, tolerance: float) -> dict:
    """Colab (GPU) vs local CPU probabilities of the same model: PASS = identical labels
    for every page AND max |dp| < tolerance (both numbers are reported)."""
    diff = float(np.abs(np.asarray(colab) - np.asarray(local)).max()) if len(local) else 0.0
    agreement = (
        float((np.asarray(colab).argmax(axis=1) == np.asarray(local).argmax(axis=1)).mean())
        if len(local)
        else 1.0
    )
    return {
        "n": int(len(local)),
        "max_abs_diff": round(diff, 6),
        "argmax_agreement": agreement,
        "labels_identical": agreement == 1.0,
        "tolerance": tolerance,
        "rule": "PASS if every predicted label is identical and max |dp| < tolerance "
        "(GPU vs CPU fp32 differences of ~1e-3 are expected)",
        "ok": agreement == 1.0 and diff < tolerance,
    }


def evaluate_xlmr(
    version: str,
    config: XlmrConfig | None = None,
    data: TextExamples | None = None,
    model_root: Path | None = None,
    reports_dir: Path | None = None,
    figures: bool = True,
    local_seeds: bool = True,
    log=print,
) -> dict:
    """Score final + every seed on val and test, write reports + update the model card."""
    config = config or XlmrConfig.load()
    data = data or build_examples(version)
    model_root = Path(model_root or config.models_dir(version))
    reports_dir = Path(reports_dir or config.reports_dir(version))
    final = model_root / "final"
    if not (final / WEIGHTS).is_file():
        raise FileNotFoundError(
            f"no XLM-R model in {final} - train on Colab, then: python scripts/train_xlmr.py "
            f"import-model --zip <downloaded.zip> --version {version}"
        )
    check_model_dir(model_root, data)
    labels = data.labels
    rows = data.rows("val", "test")
    selection = json.loads((final / "selection.json").read_text(encoding="utf-8"))

    log(f"final model (seed {selection['final_seed']}): predicting {len(rows)} pages on CPU ...")
    final_proba = local_predictions(final, rows, config)
    consistency = None
    colab = _colab_predictions(final, rows, len(labels))
    if colab is not None:
        consistency = consistency_check(
            colab, final_proba, float(config.inference["prediction_tolerance"])
        )
        log(
            f"Colab vs local CPU: labels identical {100 * consistency['argmax_agreement']:.1f} %, "
            f"max |dp| {consistency['max_abs_diff']:.4g} (< {consistency['tolerance']}) -> "
            f"{'PASS' if consistency['ok'] else 'CHECK'}"
        )

    models, wrong_all = {}, []
    entry, wrong = _score("final", rows, final_proba, data, config)
    models["final"] = {
        "display_name": f"{XLMR_DISPLAY} - final (seed {selection['final_seed']})",
        "seed": selection["final_seed"],
        "source": "local-cpu",
        **entry,
    }
    wrong_all += wrong
    seed_runs = {"val": [], "test": []}
    for seed, folder in seed_dirs(model_root):
        if seed == selection["final_seed"]:
            proba, source = final_proba, "local-cpu (= final)"
        elif local_seeds and (folder / WEIGHTS).is_file():
            log(f"seed {seed}: predicting on CPU ...")
            proba, source = local_predictions(folder, rows, config), "local-cpu"
        else:
            proba, source = _colab_predictions(folder, rows, len(labels)), "colab predictions"
            if proba is None:
                raise StaleModelError(f"seed {seed} has neither weights nor full predictions")
        entry, wrong = _score(f"seed_{seed}", rows, proba, data, config)
        models[f"seed_{seed}"] = {
            "display_name": f"{XLMR_DISPLAY} - seed {seed}",
            "seed": seed,
            "source": source,
            **entry,
        }
        wrong_all += wrong
        seed_runs["val"].append(entry["val"])
        seed_runs["test"].append(entry["test"])

    card_path = model_root / "model_card.json"
    card = json.loads(card_path.read_text(encoding="utf-8")) if card_path.is_file() else {}
    results = {
        "arm": "text (XLM-R)",
        "version": version,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "classes": labels,
        "split": {
            "split_fingerprint": data.meta["split_fingerprint"],
            "counts": data.meta["counts"],
        },
        "manifest_fingerprint": data.meta["manifest_fingerprint"],
        "text_schema_version": data.meta["text_schema_version"],
        "text_rules_hash": data.meta["text_rules_hash"],
        "base_model": card.get("base_model"),
        "smoke": card.get("smoke", False),
        "selection": SELECTION_RULE,
        "final_seed": selection["final_seed"],
        "best_model": "final",
        "models": models,
        "seed_summary": {k: seed_summary(v) for k, v in seed_runs.items() if v},
        "consistency": consistency,
        "misclassified_total": sum(1 for row in wrong_all if row["model"] == "final"),
    }
    write_json(results, reports_dir / "results.json")
    atomic_write_text(render_results_md(results), reports_dir / "results.md")
    write_csv(pd.DataFrame(wrong_all), reports_dir / "misclassified.csv")
    if figures:
        for name, model in models.items():
            for split_name in ("test", "val") if name == "final" else ("test",):
                plot_confusion_matrix(
                    model[split_name]["confusion_matrix"],
                    labels,
                    f"{model['display_name']} - {split_name} ({version})",
                    reports_dir / "figures" / f"confusion_{name}_{split_name}.png",
                )
    if card:
        for name, model in models.items():
            if name.startswith("seed_") and str(model["seed"]) in card.get("seeds", {}):
                card["seeds"][str(model["seed"])]["test"] = {
                    key: model["test"][key] for key in TEXT_SCALARS
                }
        card["final_test"] = {key: models["final"]["test"][key] for key in TEXT_SCALARS}
        card["test_seed_summary"] = results["seed_summary"].get("test")
        card["evaluated_at"] = results["created_at"]
        write_json(card, card_path)
    return results


# ---- ablation --------------------------------------------------------------------------------


def ablation(
    version: str, config: XlmrConfig | None = None, data: TextExamples | None = None
) -> tuple[list[dict], str, str]:
    """(rows, markdown, terminal text) of DOM / Behavior / TF-IDF / XLM-R on ``version``.

    Also written to reports/xlmr/<version>/ablation.{json,md}.
    """
    config = config or XlmrConfig.load()
    data = data or build_examples(version)
    main = load_yaml_config("config")

    def results_of(section: str, default: str) -> Path:
        folder = main.get(section, {}).get("reports_dir", default)
        return resolve_path(Path(folder)) / version / "results.json"

    paths = {
        "DOM-only": results_of("dom_baseline", "reports/dom_baseline"),
        "Behavior-only": results_of("behavior_baseline", "reports/behavior_baseline"),
        "Text TF-IDF": config.baseline_reports_dir(version) / "results.json",
        "Text XLM-R": config.reports_dir(version) / "results.json",
    }
    rows = ablation_rows(paths, data.meta["split_fingerprint"])
    markdown = render_ablation_md(rows, version, data.labels)
    out = config.reports_dir(version)
    write_json({"version": version, "rows": rows}, out / "ablation.json")
    atomic_write_text(markdown, out / "ablation.md")
    return rows, markdown, ablation_text(rows, data.labels)
