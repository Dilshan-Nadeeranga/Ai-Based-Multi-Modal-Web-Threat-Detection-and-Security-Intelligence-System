"""Train and evaluate the Text + OCR threat baseline (DistilBERT, binary is_scam).

Requires ``scripts/prepare_text_baseline.py`` to have written
``data/annotations/text_baseline_dataset.jsonl``.

Steps (checklist items):
  Tokenize text, Select baseline transformer, Train / Validate / Test,
  Precision/Recall/F1, Confusion matrix, Save trained model.

Writes:
  models/text_baseline/<run>/                       — model + tokenizer (best val F1)
  data/statistics/text_baseline_tokenization.json
  data/statistics/text_baseline_metrics.json
  data/statistics/text_baseline_confusion_matrix.png

Usage:
  python scripts/train_text_baseline.py
  python scripts/train_text_baseline.py --epochs 4 --max-length 256 --batch-size 8
"""

from __future__ import annotations

import argparse
import json
import random
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap

try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

import numpy as np
import torch
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from torch.utils.data import DataLoader, TensorDataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

from prepare_text_baseline import DATASET, mark_checklist

ROOT = _bootstrap.SERVICE_ROOT
STATS_DIR = ROOT / "data" / "statistics"
TOKENIZATION = STATS_DIR / "text_baseline_tokenization.json"
METRICS = STATS_DIR / "text_baseline_metrics.json"
CONFUSION_PNG = STATS_DIR / "text_baseline_confusion_matrix.png"
MODELS_DIR = ROOT / "models" / "text_baseline"

DEFAULT_MODEL = "distilbert-base-uncased"
LABELS = {0: "legitimate", 1: "scam"}


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_rows(extra: list[Path] | None = None) -> dict[str, list[dict]]:
    rows = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    for path in extra or []:
        rows += [dict(json.loads(line), extra_source=True) for line in path.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
    return {split: [row for row in rows if row["split"] == split] for split in ("train", "val", "test")}


def tokenize(tokenizer, rows: list[dict], max_length: int) -> tuple[TensorDataset, dict]:
    texts = [row["text"] for row in rows]
    full_lengths = [len(ids) for ids in tokenizer(texts, truncation=False)["input_ids"]]
    encoded = tokenizer(texts, truncation=True, max_length=max_length, padding="max_length", return_tensors="pt")
    labels = torch.tensor([row["label"] for row in rows], dtype=torch.long)
    unk = tokenizer.unk_token_id
    unk_rate = float((encoded["input_ids"] == unk).sum()) / max(1, int(encoded["attention_mask"].sum()))
    stats = {
        "samples": len(rows),
        "tokens_p50": int(np.percentile(full_lengths, 50)),
        "tokens_p90": int(np.percentile(full_lengths, 90)),
        "tokens_max": int(max(full_lengths)),
        "truncated": sum(1 for n in full_lengths if n > max_length),
        "unk_rate": round(unk_rate, 5),
    }
    return TensorDataset(encoded["input_ids"], encoded["attention_mask"], labels), stats


@torch.no_grad()
def predict(model, loader) -> tuple[list[int], list[int], list[float]]:
    model.eval()
    y_true, y_pred, p_scam = [], [], []
    for input_ids, attention_mask, labels in loader:
        logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
        probs = torch.softmax(logits, dim=-1)[:, 1]
        y_true.extend(labels.tolist())
        y_pred.extend(logits.argmax(dim=-1).tolist())
        p_scam.extend(probs.tolist())
    return y_true, y_pred, p_scam


def scores(y_true: list[int], y_pred: list[int]) -> dict:
    precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=[0, 1], zero_division=0)
    macro = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    return {
        "accuracy": round(float(np.mean(np.array(y_true) == np.array(y_pred))), 4),
        "precision_scam": round(float(precision[1]), 4),
        "recall_scam": round(float(recall[1]), 4),
        "f1_scam": round(float(f1[1]), 4),
        "per_class": {
            LABELS[k]: {"precision": round(float(precision[k]), 4), "recall": round(float(recall[k]), 4),
                        "f1": round(float(f1[k]), 4), "support": int(support[k])}
            for k in (0, 1)
        },
        "macro": {"precision": round(float(macro[0]), 4), "recall": round(float(macro[1]), 4), "f1": round(float(macro[2]), 4)},
        "confusion_matrix": {"labels": [LABELS[0], LABELS[1]], "rows_true_cols_pred": matrix.tolist()},
    }


def plot_confusion(matrix: list[list[int]], title: str, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    data = np.array(matrix)
    fig, ax = plt.subplots(figsize=(4.2, 3.8), dpi=150)
    ax.imshow(data, cmap="Greens")
    names = [LABELS[0], LABELS[1]]
    ax.set_xticks([0, 1], names)
    ax.set_yticks([0, 1], names)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title(title, fontsize=9)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(data[i, j]), ha="center", va="center",
                    color="white" if data[i, j] > data.max() / 2 else "black", fontsize=12)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--lr", type=float, default=3e-5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--extra-jsonl", type=Path, action="append", default=[],
                        help="Extra rows in the text_baseline_dataset format (e.g. data/raw/telephish/...); kept out of Git")
    args = parser.parse_args()

    set_seed(args.seed)
    splits = load_rows(args.extra_jsonl)
    run_name = args.model.split("/")[-1]
    output_dir = MODELS_DIR / run_name
    STATS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[model] {args.model}  train={len(splits['train'])} val={len(splits['val'])} test={len(splits['test'])}")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    datasets, token_stats = {}, {}
    for split, rows in splits.items():
        datasets[split], token_stats[split] = tokenize(tokenizer, rows, args.max_length)
    TOKENIZATION.write_text(json.dumps({
        "tokenizer": args.model, "max_length": args.max_length, "splits": token_stats,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")
    mark_checklist("Tokenize text", True)
    print(f"[tokenize] {token_stats}")

    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=2, id2label=LABELS, label2id={v: k for k, v in LABELS.items()},
    )
    mark_checklist("Select baseline transformer", True)

    generator = torch.Generator().manual_seed(args.seed)
    train_loader = DataLoader(datasets["train"], batch_size=args.batch_size, shuffle=True, generator=generator)
    val_loader = DataLoader(datasets["val"], batch_size=args.batch_size * 2)
    test_loader = DataLoader(datasets["test"], batch_size=args.batch_size * 2)

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    total_steps = len(train_loader) * args.epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, int(0.1 * total_steps), total_steps)

    history, best_f1, best_epoch = [], -1.0, 0
    started = time.time()
    for epoch in range(1, args.epochs + 1):
        model.train()
        losses = []
        for input_ids, attention_mask, labels in train_loader:
            optimizer.zero_grad()
            loss = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            losses.append(loss.item())
        y_true, y_pred, _ = predict(model, val_loader)
        val = scores(y_true, y_pred)
        history.append({"epoch": epoch, "train_loss": round(float(np.mean(losses)), 4),
                        "val_f1_scam": val["f1_scam"], "val_accuracy": val["accuracy"]})
        print(f"[epoch {epoch}] loss={history[-1]['train_loss']} val_f1={val['f1_scam']} "
              f"val_acc={val['accuracy']} ({time.time() - started:.0f}s)")
        if val["f1_scam"] > best_f1:
            best_f1, best_epoch = val["f1_scam"], epoch
            model.save_pretrained(output_dir)
            tokenizer.save_pretrained(output_dir)
    mark_checklist("Train text baseline", True)

    model = AutoModelForSequenceClassification.from_pretrained(output_dir)
    y_true, y_pred, _ = predict(model, val_loader)
    val_scores = scores(y_true, y_pred)
    mark_checklist("Validate text baseline", True)

    y_true, y_pred, p_scam = predict(model, test_loader)
    test_scores = scores(y_true, y_pred)
    mark_checklist("Test text baseline", True)

    by_source = {}
    for source in sorted({row["source_dataset"] for row in splits["test"]}):
        idx = [i for i, row in enumerate(splits["test"]) if row["source_dataset"] == source]
        part = scores([y_true[i] for i in idx], [y_pred[i] for i in idx])
        by_source[source] = {"n": len(idx), "accuracy": part["accuracy"], "f1_scam": part["f1_scam"],
                             "confusion_matrix": part["confusion_matrix"]["rows_true_cols_pred"]}
    original = [i for i, row in enumerate(splits["test"]) if not row.get("extra_source")]
    test_original = scores([y_true[i] for i in original], [y_pred[i] for i in original]) if args.extra_jsonl else None
    errors = [
        {"sample_id": row["sample_id"], "source_dataset": row["source_dataset"], "label": y_true[i],
         "pred": y_pred[i], "p_scam": round(p_scam[i], 4)}
        for i, row in enumerate(splits["test"]) if y_true[i] != y_pred[i]
    ]

    METRICS.write_text(json.dumps({
        "model": args.model,
        "saved_model": str(output_dir.relative_to(ROOT)).replace("\\", "/"),
        "hyperparameters": {"epochs": args.epochs, "batch_size": args.batch_size, "max_length": args.max_length,
                            "lr": args.lr, "seed": args.seed, "device": "cpu"},
        "best_epoch": best_epoch,
        "history": history,
        "validation": val_scores,
        "test": test_scores,
        "test_original_rows": test_original,
        "extra_sources": [str(p).replace("\\", "/") for p in args.extra_jsonl],
        "test_by_source": by_source,
        "test_errors": errors,
        "label_counts": {split: dict(Counter(row["label"] for row in rows)) for split, rows in splits.items()},
        "training_seconds": round(time.time() - started, 1),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")
    mark_checklist("Calculate Precision/Recall/F1", True)

    plot_confusion(test_scores["confusion_matrix"]["rows_true_cols_pred"],
                   f"{run_name} test (n={len(y_true)}, F1={test_scores['f1_scam']})", CONFUSION_PNG)
    mark_checklist("Generate confusion matrix", True)
    mark_checklist("Save trained model", True)

    print(f"[val]  {json.dumps({k: val_scores[k] for k in ('accuracy', 'precision_scam', 'recall_scam', 'f1_scam')})}")
    print(f"[test] {json.dumps({k: test_scores[k] for k in ('accuracy', 'precision_scam', 'recall_scam', 'f1_scam')})}")
    print(f"[test] confusion (rows=true legit/scam, cols=pred) {test_scores['confusion_matrix']['rows_true_cols_pred']}")
    print(f"[test] by source {json.dumps({k: (v['n'], v['accuracy']) for k, v in by_source.items()})}")
    if test_original:
        print(f"[test original rows] {json.dumps({k: test_original[k] for k in ('accuracy', 'precision_scam', 'recall_scam', 'f1_scam')})}")
    print(f"Saved model to {output_dir}")


if __name__ == "__main__":
    main()
