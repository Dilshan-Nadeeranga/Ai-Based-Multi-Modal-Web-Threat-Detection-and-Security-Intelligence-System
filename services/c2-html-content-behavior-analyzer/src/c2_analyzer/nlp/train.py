"""Fine-tune XLM-R on page_text, 3 seeds, pick the final model (tasks 6-7).

Part 6: XLM-R content classification (6A, page level). PORTABLE module: copied into
the Colab bundle as ``c2_nlp/train.py`` (``python run_train.py`` there), so it must not
import ``c2_analyzer``. The repo uses the same code (``train_xlmr.py train``).

Input: an examples folder written by ``nlp/dataset.py::export_examples``
(train / val / test .jsonl, label_mapping.json, examples_meta.json with the split
fingerprint). Output per seed ``<out>/seed_<n>/`` (model.safetensors + config.json +
tokenizer + training_args.json + label_mapping.json + metrics.json + predictions.jsonl),
``<out>/final/`` (copy of the best seed + selection.json), ``<out>/model_card.json``.

Design decisions (viva):
- **Why 3 seeds:** with ~322 training pages the score of ONE fine-tuning run depends a
  lot on luck (head initialisation, batch order). Three seeds give mean ± std, so a
  difference to the DOM / Behavior baselines can be judged against that noise.
- **Class-weighted cross-entropy:** benign is ~half of train and crypto_scam ~7 %.
  weight_c = n / (k * n_c) makes each class count the same in the loss, matching the
  macro-F1 goal (and Part 4's class_weight="balanced").
- **Early stopping on VAL macro-F1** (patience 3, best epoch restored): small data
  overfits after a few epochs; val decides how long to train.
- **Final model = the seed with the best VAL macro-F1** - chosen without test.
- **Test is used once:** training and selection never use test.jsonl. After the
  selection, every seed writes val + test probabilities (``predictions.jsonl``) so the
  ~1 GB final model is the only download needed; ``evaluate_xlmr.py`` computes the
  test metrics once from them and re-checks the final model on the local CPU.

CV / OOF mode (Part 9A, ``run_train.py --cv``; bundle from ``export-bundle --cv``):
the fusion stacker needs XLM-R probabilities for every train+val page from a model that
NEVER saw that page. For each of the 5 shared grouped folds k: train on the other folds
minus an inner-validation slice, early-stop on that inner slice (cluster-pure, chosen on
the laptop, never the test split - the CV bundle does not even contain test pages), then
predict ONLY fold k. Same hyperparameters as above, one seed (Part 6A's final seed).
Only the predictions are kept (``oof/fold_<k>.jsonl`` + ``oof_meta.json``, a few KB);
the fold weights are deleted, so the download is tiny. A finished fold is skipped on a
re-run (a Colab disconnect does not lose the folds already done).
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

from .model import build_model, predict_proba
from .tokenizer import load_tokenizer

SPLITS = ("train", "val", "test")
LABEL_MAPPING_FILE = "label_mapping.json"
META_FILE = "examples_meta.json"
SELECTION_RULE = "seed with the highest VAL macro-F1 (ties: lower seed); test never used"
CV_EXAMPLES_FILE = "cv_examples.jsonl"  # train+val pages with their shared CV fold
CV_PLAN_FILE = "cv_plan.json"  # seed + the inner-validation ids of every fold
OOF_DIR = "oof"
OOF_META_FILE = "oof_meta.json"


# ---- files ---------------------------------------------------------------------------------


def read_jsonl(path: Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(rows: list[dict], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


def write_json(data: Any, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


@dataclass
class Examples:
    """The exported examples of one dataset version (see nlp/dataset.py)."""

    labels: list[str]
    rows: dict[str, list[dict]]
    label_mapping: dict
    meta: dict = field(default_factory=dict)


def load_examples(folder: Path) -> Examples:
    folder = Path(folder)
    mapping = json.loads((folder / LABEL_MAPPING_FILE).read_text(encoding="utf-8"))
    meta_path = folder / META_FILE
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    rows = {split: read_jsonl(folder / f"{split}.jsonl") for split in SPLITS}
    return Examples(labels=list(mapping["classes"]), rows=rows, label_mapping=mapping, meta=meta)


# ---- small helpers -------------------------------------------------------------------------


def class_weights(label_ids: list[int], n_classes: int) -> list[float]:
    """Balanced weights n / (k * n_c); a class absent from train gets weight 0."""
    counts = Counter(int(i) for i in label_ids)
    n = sum(counts.values())
    return [n / (n_classes * counts[c]) if counts[c] else 0.0 for c in range(n_classes)]


def smoke_subset(rows: list[dict], per_class: int) -> list[dict]:
    """The first ``per_class`` rows of every class (deterministic)."""
    taken: Counter = Counter()
    subset = []
    for row in rows:
        if taken[row["label_id"]] < per_class:
            taken[row["label_id"]] += 1
            subset.append(row)
    return subset


def macro_f1_metrics(n_classes: int):
    """compute_metrics for the HF Trainer: macro-F1 over ALL classes (+ accuracy)."""
    from sklearn.metrics import accuracy_score, f1_score

    def compute(eval_pred) -> dict[str, float]:
        logits, labels = eval_pred
        logits = logits[0] if isinstance(logits, tuple) else logits
        predicted = np.asarray(logits).argmax(axis=-1)
        return {
            "macro_f1": float(
                f1_score(
                    labels,
                    predicted,
                    labels=list(range(n_classes)),
                    average="macro",
                    zero_division=0,
                )
            ),
            "accuracy": float(accuracy_score(labels, predicted)),
        }

    return compute


def library_versions() -> dict[str, str]:
    import sklearn
    import tokenizers
    import torch
    import transformers

    versions = {
        "python": platform.python_version(),
        "torch": torch.__version__,
        "transformers": transformers.__version__,
        "tokenizers": tokenizers.__version__,
        "numpy": np.__version__,
        "scikit-learn": sklearn.__version__,
        "cuda": str(torch.version.cuda),
    }
    for name in ("accelerate", "safetensors", "sentencepiece"):
        try:
            versions[name] = __import__(name).__version__
        except ImportError:  # pragma: no cover - optional at inference time
            pass
    return versions


def device_info() -> dict[str, Any]:
    import torch

    if torch.cuda.is_available():
        return {"device": "cuda", "gpu_name": torch.cuda.get_device_name(0)}
    return {"device": "cpu", "gpu_name": None}


# ---- the Trainer ---------------------------------------------------------------------------


def _encoded_dataset(tokenizer: Any, rows: list[dict], max_length: int):
    import torch

    encodings = tokenizer(
        [row["text"] for row in rows], truncation=True, max_length=max_length, padding=False
    )
    labels = [int(row["label_id"]) for row in rows]

    class EncodedPages(torch.utils.data.Dataset):
        def __len__(self) -> int:
            return len(labels)

        def __getitem__(self, i: int) -> dict:
            item = {key: values[i] for key, values in encodings.items()}
            item["labels"] = labels[i]
            return item

    return EncodedPages()


def weighted_trainer_class():
    """Trainer subclass with class-weighted cross-entropy (custom compute_loss)."""
    import torch
    from transformers import Trainer

    class WeightedTrainer(Trainer):
        def __init__(self, *args, class_weights: list[float], **kwargs) -> None:
            super().__init__(*args, **kwargs)
            self.class_weight_tensor = torch.tensor(class_weights, dtype=torch.float32)
            # Our loss is a per-batch MEAN, so the Trainer must divide it by the
            # gradient-accumulation steps (it skips that for models that accept
            # loss kwargs, which would make accumulated gradients too large).
            self.model_accepts_loss_kwargs = False

        def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            loss = torch.nn.functional.cross_entropy(
                outputs.logits.float(),
                labels,
                weight=self.class_weight_tensor.to(outputs.logits.device),
            )
            return (loss, outputs) if return_outputs else loss

    return WeightedTrainer


def _best_epoch(history: list[dict], best: float | None) -> float | None:
    for entry in history:
        if best is not None and entry.get("eval_macro_f1") == best:
            return entry.get("epoch")
    return None


def fit_trainer(
    train_rows: list[dict],
    val_rows: list[dict],
    labels: list[str],
    config: dict,
    model_name: str,
    seed: int,
    work_dir: Path,
    weights: list[float],
    max_length: int,
    smoke: bool = False,
):
    """Fine-tune one model: early stopping on ``val_rows`` macro-F1, best epoch restored.

    Shared by the 3-seed training (train_seed) and the CV / OOF mode (train_cv), so both
    use exactly the same Trainer settings. Returns (trainer, tokenizer, args, seconds).
    """
    import torch
    from transformers import DataCollatorWithPadding, EarlyStoppingCallback, TrainingArguments
    from transformers import set_seed as hf_set_seed

    t = config["training"]
    hf_set_seed(seed)  # the new classification head is initialised from this seed
    tokenizer = load_tokenizer(model_name)
    model = build_model(model_name, labels)
    cuda = torch.cuda.is_available()
    arguments = {
        "output_dir": str(Path(work_dir) / "_checkpoints"),
        "learning_rate": float(t["learning_rate"]),
        "num_train_epochs": float(t["epochs"]),
        "per_device_train_batch_size": int(t["batch_size"]),
        "per_device_eval_batch_size": int(t["eval_batch_size"]),
        "gradient_accumulation_steps": int(t["gradient_accumulation"]),
        "warmup_ratio": float(t["warmup_ratio"]),
        "weight_decay": float(t["weight_decay"]),
        "max_grad_norm": float(t["max_grad_norm"]),
        "fp16": bool(t["fp16"]) and cuda,
        "use_cpu": not cuda,
        "eval_strategy": "epoch",
        "save_strategy": "epoch",
        "logging_strategy": "epoch",
        "save_total_limit": 1,  # the best checkpoint is always kept as well
        "save_only_model": True,  # no optimizer state: 1.1 GB per checkpoint instead of 3.3
        "load_best_model_at_end": True,
        "metric_for_best_model": "macro_f1",
        "greater_is_better": True,
        "report_to": "none",
        "seed": seed,
        "data_seed": seed,
        "dataloader_num_workers": 0,
    }
    if smoke:
        arguments.update(
            max_steps=int(config["smoke"]["max_steps"]),
            eval_strategy="steps",
            save_strategy="steps",
            logging_strategy="steps",
            eval_steps=1,
            save_steps=1,
            logging_steps=1,
            disable_tqdm=True,
        )
    args = TrainingArguments(**arguments)
    trainer = weighted_trainer_class()(
        model=model,
        args=args,
        train_dataset=_encoded_dataset(tokenizer, train_rows, max_length),
        eval_dataset=_encoded_dataset(tokenizer, val_rows, max_length),
        data_collator=DataCollatorWithPadding(tokenizer),
        processing_class=tokenizer,
        compute_metrics=macro_f1_metrics(len(labels)),
        callbacks=[EarlyStoppingCallback(early_stopping_patience=int(t["patience"]))],
        class_weights=weights,
    )
    started = time.perf_counter()
    trainer.train()
    return trainer, tokenizer, args, time.perf_counter() - started


def train_seed(
    data: Examples,
    config: dict,
    model_name: str,
    seed: int,
    out_dir: Path,
    smoke: bool = False,
    log=print,
) -> dict:
    """Fine-tune one seed, save the best epoch to ``out_dir``; returns metrics.json."""
    out_dir = Path(out_dir)
    labels = data.labels
    t = config["training"]
    max_length = int(config["max_length"])
    train_rows, val_rows = data.rows["train"], data.rows["val"]
    if smoke:
        per_class = int(config["smoke"]["per_class"])
        train_rows, val_rows = smoke_subset(train_rows, per_class), smoke_subset(val_rows, 1)
        max_length = int(config["smoke"]["max_length"])
    weights = class_weights([row["label_id"] for row in data.rows["train"]], len(labels))

    trainer, tokenizer, args, seconds = fit_trainer(
        train_rows, val_rows, labels, config, model_name, seed, out_dir, weights, max_length, smoke
    )
    best = trainer.state.best_metric
    history = trainer.state.log_history

    out_dir.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(out_dir))  # best epoch (load_best_model_at_end) as safetensors
    tokenizer.save_pretrained(str(out_dir))
    write_json(args.to_dict(), out_dir / "training_args.json")
    write_json(data.label_mapping, out_dir / LABEL_MAPPING_FILE)
    shutil.rmtree(out_dir / "_checkpoints", ignore_errors=True)

    # val + test probabilities of the saved model (fp32, same code as local inference)
    predictions = []
    for split in ("val", "test"):
        rows = val_rows if (smoke and split == "val") else data.rows[split]
        if smoke and split == "test":
            rows = smoke_subset(rows, 1)
        proba = predict_proba(
            trainer.model,
            tokenizer,
            [row["text"] for row in rows],
            max_length,
            int(t["eval_batch_size"]),
        )
        predictions += [
            {
                "sample_id": row["sample_id"],
                "split": split,
                "label_id": int(row["label_id"]),
                "probabilities": [round(float(p), 6) for p in probs],
            }
            for row, probs in zip(rows, proba, strict=True)
        ]
    write_jsonl(predictions, out_dir / "predictions.jsonl")

    metrics = {
        "seed": seed,
        "model_name": str(model_name),
        "smoke": smoke,
        "dataset_version": data.meta.get("dataset_version"),
        "split_fingerprint": data.meta.get("split_fingerprint"),
        "manifest_fingerprint": data.meta.get("manifest_fingerprint"),
        "text_schema_version": data.meta.get("text_schema_version"),
        "text_rules_hash": data.meta.get("text_rules_hash"),
        "classes": labels,
        "n_train": len(train_rows),
        "n_val": len(val_rows),
        "max_length": max_length,
        "class_weights": dict(zip(labels, weights, strict=True)),
        "best_val_macro_f1": best,
        "best_epoch": _best_epoch(history, best),
        "epochs_run": trainer.state.epoch,
        "global_steps": trainer.state.global_step,
        "training_seconds": round(seconds, 1),
        "log_history": history,
        **device_info(),
        "library_versions": library_versions(),
        "trained_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    write_json(metrics, out_dir / "metrics.json")
    log(
        f"seed {seed}: best val macro-F1 {best if best is None else round(best, 4)} at epoch "
        f"{metrics['best_epoch']} ({metrics['epochs_run']} epochs, {seconds:.0f} s, "
        f"{metrics['device']} {metrics['gpu_name'] or ''})"
    )
    return metrics


def select_final(out_root: Path, seed_metrics: list[dict]) -> dict:
    """Copy the seed with the best VAL macro-F1 to ``<out_root>/final``."""
    out_root = Path(out_root)
    ranked = sorted(seed_metrics, key=lambda m: (-(m["best_val_macro_f1"] or 0.0), m["seed"]))
    chosen = ranked[0]["seed"]
    final = out_root / "final"
    shutil.rmtree(final, ignore_errors=True)
    shutil.copytree(out_root / f"seed_{chosen}", final)
    selection = {
        "final_seed": chosen,
        "rule": SELECTION_RULE,
        "val_macro_f1": {str(m["seed"]): m["best_val_macro_f1"] for m in seed_metrics},
    }
    write_json(selection, final / "selection.json")
    return selection


def model_card(data: Examples, config: dict, model_name: str, seeds: list[dict], selection):
    """model_card.json (like Part 4's); evaluate_xlmr.py adds the test metrics."""
    first = seeds[0]
    return {
        "name": "XLM-R page_text classifier (Part 6A, NLP-only arm)",
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "dataset_version": data.meta.get("dataset_version"),
        "manifest_fingerprint": data.meta.get("manifest_fingerprint"),
        "split_fingerprint": data.meta.get("split_fingerprint"),
        "text_schema_version": data.meta.get("text_schema_version"),
        "text_rules_hash": data.meta.get("text_rules_hash"),
        "base_model": str(model_name),
        "smoke": first["smoke"],
        "label_mapping": data.label_mapping,
        "hyperparameters": {
            "max_length": config["max_length"],
            "seeds": [m["seed"] for m in seeds],
            **config["training"],
        },
        "selection": selection,
        "seeds": {
            str(m["seed"]): {
                "val_macro_f1": m["best_val_macro_f1"],
                "best_epoch": m["best_epoch"],
                "epochs_run": m["epochs_run"],
                "training_seconds": m["training_seconds"],
                "test": None,  # filled by evaluate_xlmr.py (test is used once)
            }
            for m in seeds
        },
        "device": first["device"],
        "gpu_name": first["gpu_name"],
        "library_versions": first["library_versions"],
        "git_commit": data.meta.get("git_commit"),
        "intended_use": "Research: the NLP-only arm of C2's ablation study (page text -> "
        "threat class). Not a stand-alone production detector.",
        "limitations": "Small dataset (~322 train pages, mostly English, very few si / ta); "
        "page_text over 512 tokens is truncated; labels are mostly unverified.",
    }


def train_all(
    examples_dir: Path,
    out_root: Path,
    config: dict,
    model_name: str,
    seeds: list[int] | None = None,
    smoke: bool = False,
    log=print,
) -> dict:
    """Train every seed, select the final model, write the model card. Returns the card."""
    data = load_examples(examples_dir)
    out_root = Path(out_root)
    seeds = [int(s) for s in (seeds or config["seeds"])]
    info = device_info()
    log(f"device: {info['device']} {info['gpu_name'] or ''} · model {model_name} · seeds {seeds}")
    results = []
    for seed in seeds:
        results.append(
            train_seed(data, config, model_name, seed, out_root / f"seed_{seed}", smoke, log)
        )
    selection = select_final(out_root, results)
    write_json(data.label_mapping, out_root / LABEL_MAPPING_FILE)
    card = model_card(data, config, model_name, results, selection)
    write_json(card, out_root / "model_card.json")
    log(f"final model = seed {selection['final_seed']} -> {out_root / 'final'}")
    return card


# ---- CV / OOF mode (Part 9A) -----------------------------------------------------------------


def load_cv_examples(folder: Path) -> tuple[Examples, list[dict], dict]:
    """(Examples with label mapping + meta, train+val rows with "fold", cv_plan.json)."""
    folder = Path(folder)
    mapping = json.loads((folder / LABEL_MAPPING_FILE).read_text(encoding="utf-8"))
    meta = json.loads((folder / META_FILE).read_text(encoding="utf-8"))
    plan = json.loads((folder / CV_PLAN_FILE).read_text(encoding="utf-8"))
    rows = read_jsonl(folder / CV_EXAMPLES_FILE)
    data = Examples(labels=list(mapping["classes"]), rows={}, label_mapping=mapping, meta=meta)
    return data, rows, plan


def fold_roles(rows: list[dict], plan: dict, fold: int) -> tuple[list, list, list]:
    """(train, inner validation, held-out) rows of one fold. The held-out fold is never in
    train or inner validation, so its predictions are truly out-of-fold."""
    inner = set(plan["folds"][str(fold)]["inner_val"])
    held = [row for row in rows if int(row["fold"]) == fold]
    val = [row for row in rows if int(row["fold"]) != fold and row["sample_id"] in inner]
    train = [row for row in rows if int(row["fold"]) != fold and row["sample_id"] not in inner]
    return train, val, held


def train_cv_fold(
    data: Examples,
    rows: list[dict],
    plan: dict,
    config: dict,
    model_name: str,
    fold: int,
    out_root: Path,
    seed: int,
    smoke: bool = False,
    log=print,
) -> dict:
    """Train fold ``fold``'s model, write ``oof/fold_<k>.jsonl``, delete the weights."""
    out_root = Path(out_root)
    labels = data.labels
    train_rows, val_rows, held = fold_roles(rows, plan, fold)
    max_length = int(config["max_length"])
    weights = class_weights([row["label_id"] for row in train_rows], len(labels))
    if smoke:
        per_class = int(config["smoke"]["per_class"])
        train_rows, val_rows = smoke_subset(train_rows, per_class), smoke_subset(val_rows, 1)
        max_length = int(config["smoke"]["max_length"])
    work = out_root / "_work" / f"fold_{fold}"
    trainer, tokenizer, _, seconds = fit_trainer(
        train_rows, val_rows, labels, config, model_name, seed, work, weights, max_length, smoke
    )
    best = trainer.state.best_metric
    proba = predict_proba(
        trainer.model,
        tokenizer,
        [row["text"] for row in held],
        max_length,
        int(config["training"]["eval_batch_size"]),
    )
    predictions = [
        {
            "sample_id": row["sample_id"],
            "fold": fold,
            "label_id": int(row["label_id"]),
            "probabilities": [round(float(p), 6) for p in probs],
        }
        for row, probs in zip(held, proba, strict=True)
    ]
    write_jsonl(predictions, out_root / OOF_DIR / f"fold_{fold}.jsonl")
    summary = {
        "fold": fold,
        "n_train": len(train_rows),
        "n_inner_val": len(val_rows),
        "n_heldout": len(held),
        "best_inner_val_macro_f1": best,
        "best_epoch": _best_epoch(trainer.state.log_history, best),
        "epochs_run": trainer.state.epoch,
        "training_seconds": round(seconds, 1),
    }
    write_json(summary, out_root / OOF_DIR / f"fold_{fold}_metrics.json")
    del trainer
    shutil.rmtree(work, ignore_errors=True)  # weights are not needed: predictions only
    log(
        f"fold {fold}: train {summary['n_train']}, inner val {summary['n_inner_val']}, "
        f"held out {summary['n_heldout']} - best inner-val macro-F1 "
        f"{best if best is None else round(best, 4)} at epoch {summary['best_epoch']} "
        f"({seconds:.0f} s)"
    )
    return summary


def train_cv(
    examples_dir: Path,
    out_root: Path,
    config: dict,
    model_name: str,
    seed: int | None = None,
    folds: list[int] | None = None,
    smoke: bool = False,
    log=print,
) -> dict:
    """Every fold (finished folds are skipped) -> oof/ + oof_meta.json. Returns the meta."""
    data, rows, plan = load_cv_examples(examples_dir)
    out_root = Path(out_root)
    seed = int(seed if seed is not None else plan["seed"])
    all_folds = sorted(int(k) for k in plan["folds"])
    info = device_info()
    log(f"CV / OOF mode: device {info['device']} {info['gpu_name'] or ''} - model {model_name}")
    log(f"seed {seed}, folds {folds or all_folds}, {len(rows)} train+val pages (no test pages)")
    started = time.perf_counter()
    for fold in folds or all_folds:
        if (out_root / OOF_DIR / f"fold_{fold}.jsonl").is_file():
            log(f"fold {fold}: already done - skipped (delete oof/fold_{fold}.jsonl to redo)")
            continue
        train_cv_fold(data, rows, plan, config, model_name, fold, out_root, seed, smoke, log)
    done = [k for k in all_folds if (out_root / OOF_DIR / f"fold_{k}.jsonl").is_file()]
    fold_metrics = [
        json.loads((out_root / OOF_DIR / f"fold_{k}_metrics.json").read_text(encoding="utf-8"))
        for k in done
        if (out_root / OOF_DIR / f"fold_{k}_metrics.json").is_file()
    ]
    meta = {
        "mode": "cv_oof",
        "model_name": str(model_name),
        "seed": seed,
        "smoke": smoke,
        "dataset_version": data.meta.get("dataset_version"),
        "split_fingerprint": data.meta.get("split_fingerprint"),
        "cv_folds_fingerprint": data.meta.get("cv_folds_fingerprint"),
        "manifest_fingerprint": data.meta.get("manifest_fingerprint"),
        "text_rules_hash": data.meta.get("text_rules_hash"),
        "classes": data.labels,
        "label_mapping": data.label_mapping,
        "folds_expected": all_folds,
        "folds_done": done,
        "complete": done == all_folds,
        "fold_metrics": fold_metrics,
        "hyperparameters": {"max_length": config["max_length"], **config["training"]},
        "this_run_seconds": round(time.perf_counter() - started, 1),
        **info,
        "library_versions": library_versions(),
        "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    write_json(meta, out_root / OOF_META_FILE)
    shutil.rmtree(out_root / "_work", ignore_errors=True)
    log(f"OOF: folds done {done} of {all_folds} -> {out_root / OOF_DIR}")
    return meta


def load_config(path: Path) -> dict:
    import yaml

    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> None:
    """CLI used inside the Colab bundle (``python run_train.py``)."""
    parser = argparse.ArgumentParser(description="Fine-tune XLM-R on the exported examples")
    parser.add_argument("--examples", default="data", help="folder with train/val/test.jsonl")
    parser.add_argument("--config", default="configs/xlmr.yaml")
    parser.add_argument("--out", default=None, help="default: models/xlmr/<dataset version>")
    parser.add_argument("--seeds", type=int, nargs="+", default=None)
    parser.add_argument("--model-name", default=None, help="default: model_name in the config")
    parser.add_argument("--smoke", action="store_true", help="tiny subset, 1 step")
    parser.add_argument("--cv", action="store_true", help="CV / OOF mode (Part 9A bundle)")
    parser.add_argument("--folds", type=int, nargs="+", default=None, help="CV mode: only these")
    args = parser.parse_args(argv)
    config = load_config(Path(args.config))
    meta = json.loads((Path(args.examples) / META_FILE).read_text(encoding="utf-8"))
    if args.cv:
        out = Path(args.out or f"oof_out/{meta['dataset_version']}")
        model_name = args.model_name or config.get("model_name") or "xlm-roberta-base"
        seed = args.seeds[0] if args.seeds else None
        train_cv(Path(args.examples), out, config, model_name, seed, args.folds, args.smoke)
        return
    out = Path(args.out or f"models/xlmr/{meta['dataset_version']}")
    model_name = args.model_name or config.get("model_name") or "xlm-roberta-base"
    train_all(Path(args.examples), out, config, model_name, args.seeds, args.smoke)


if __name__ == "__main__":  # pragma: no cover
    main()
