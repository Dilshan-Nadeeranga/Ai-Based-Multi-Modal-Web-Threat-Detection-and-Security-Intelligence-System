"""Train the threat-category and misinformation text classifiers (DistilBERT).

Two tasks share this script:

  --task category       multi-class scam type on the labelled Text + OCR dataset
                        (data/annotations/text_baseline_dataset.jsonl, same splits as the binary baseline):
                        legitimate / phishing / financial_scam / data_theft
                        (brand_impersonation, malware, browser_abuse and other_scam have no labelled
                        samples; the live analyzer assigns them with evidence rules instead)
  --task misinformation binary real / fake on the Fakeddit posts in dataset_metadata.jsonl
                        (provisional subreddit-derived labels), stratified 70/15/15 by fake type

Writes:
  models/threat_category/<run>/  or  models/misinformation/<run>/
  data/statistics/{threat_category,misinformation}_metrics.json
  data/statistics/{threat_category,misinformation}_confusion_matrix.png

Usage:
  python scripts/train_threat_category.py --task category
  python scripts/train_threat_category.py --task misinformation --max-length 64
"""

from __future__ import annotations

import argparse
import json
import random
import time
from collections import Counter, defaultdict
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

from prepare_text_baseline import DATASET

ROOT = _bootstrap.SERVICE_ROOT
STATS_DIR = ROOT / "data" / "statistics"
METADATA = ROOT / "data" / "annotations" / "dataset_metadata.jsonl"
DEFAULT_MODEL = "distilbert-base-uncased"

TASKS = {
    "category": {"labels": ["legitimate", "phishing", "financial_scam", "data_theft"], "models": "threat_category",
                 "max_length": 256},
    "misinformation": {"labels": ["real", "fake"], "models": "misinformation", "max_length": 64},
}


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def category_rows(labels: list[str], extra: list[Path] | None = None) -> dict[str, list[dict]]:
    rows = [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line.strip()]
    for path in extra or []:
        rows += [dict(json.loads(line), extra_source=True) for line in path.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
    rows = [dict(row, y=labels.index(row["scam_type"]), group=row["scam_type"]) for row in rows if row["scam_type"] in labels]
    return {split: [row for row in rows if row["split"] == split] for split in ("train", "val", "test")}


def misinformation_rows(seed: int) -> dict[str, list[dict]]:
    by_type: dict[str, list[dict]] = defaultdict(list)
    for line in METADATA.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        misinfo = record["labels"].get("misinformation") or {}
        text = (record["post"].get("text") or "").strip()
        if misinfo.get("is_fake") in (0, 1) and text:
            by_type[misinfo.get("misinfo_type") or "unknown"].append({
                "sample_id": record["sample_id"], "text": text, "y": int(misinfo["is_fake"]),
                "group": misinfo.get("misinfo_type"), "source_dataset": record["source"].get("source_dataset"),
            })
    rng = random.Random(seed)
    splits: dict[str, list[dict]] = {"train": [], "val": [], "test": []}
    for group in sorted(by_type):
        items = sorted(by_type[group], key=lambda row: row["sample_id"])
        rng.shuffle(items)
        n_val = n_test = round(len(items) * 0.15)
        splits["test"] += items[:n_test]
        splits["val"] += items[n_test:n_test + n_val]
        splits["train"] += items[n_test + n_val:]
    for split, rows in splits.items():
        for row in rows:
            row["split"] = split
    return splits


def tokenize(tokenizer, rows: list[dict], max_length: int) -> TensorDataset:
    encoded = tokenizer([row["text"] for row in rows], truncation=True, max_length=max_length,
                        padding="max_length", return_tensors="pt")
    return TensorDataset(encoded["input_ids"], encoded["attention_mask"], torch.tensor([row["y"] for row in rows]))


@torch.no_grad()
def predict(model, loader) -> tuple[list[int], list[int], list[list[float]]]:
    model.eval()
    y_true, y_pred, probs = [], [], []
    for input_ids, attention_mask, labels in loader:
        logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
        y_true.extend(labels.tolist())
        y_pred.extend(logits.argmax(dim=-1).tolist())
        probs.extend(torch.softmax(logits, dim=-1).tolist())
    return y_true, y_pred, probs


def scores(y_true: list[int], y_pred: list[int], labels: list[str]) -> dict:
    ids = list(range(len(labels)))
    precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=ids, zero_division=0)
    macro = precision_recall_fscore_support(y_true, y_pred, labels=ids, average="macro", zero_division=0)
    return {
        "accuracy": round(float(np.mean(np.array(y_true) == np.array(y_pred))), 4),
        "macro": {"precision": round(float(macro[0]), 4), "recall": round(float(macro[1]), 4), "f1": round(float(macro[2]), 4)},
        "per_class": {labels[k]: {"precision": round(float(precision[k]), 4), "recall": round(float(recall[k]), 4),
                                  "f1": round(float(f1[k]), 4), "support": int(support[k])} for k in ids},
        "confusion_matrix": {"labels": labels, "rows_true_cols_pred": confusion_matrix(y_true, y_pred, labels=ids).tolist()},
    }


def plot_confusion(matrix: list[list[int]], labels: list[str], title: str, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    data = np.array(matrix)
    size = 1.2 * len(labels) + 2.2
    fig, ax = plt.subplots(figsize=(size, size - 0.4), dpi=150)
    ax.imshow(data, cmap="Blues")
    ax.set_xticks(range(len(labels)), labels, rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(labels)), labels, fontsize=8)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title(title, fontsize=9)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, str(data[i, j]), ha="center", va="center",
                    color="white" if data[i, j] > data.max() / 2 else "black", fontsize=11)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", choices=sorted(TASKS), required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-length", type=int)
    parser.add_argument("--lr", type=float, default=3e-5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--extra-jsonl", type=Path, action="append", default=[],
                        help="Extra category rows (text_baseline_dataset format), e.g. TelePhish; kept out of Git")
    args = parser.parse_args()

    task = TASKS[args.task]
    labels = task["labels"]
    max_length = args.max_length or task["max_length"]
    set_seed(args.seed)
    splits = category_rows(labels, args.extra_jsonl) if args.task == "category" else misinformation_rows(args.seed)
    run_name = args.model.split("/")[-1]
    output_dir = ROOT / "models" / task["models"] / run_name
    metrics_path = STATS_DIR / f"{task['models']}_metrics.json"
    confusion_path = STATS_DIR / f"{task['models']}_confusion_matrix.png"
    STATS_DIR.mkdir(parents=True, exist_ok=True)
    counts = {split: dict(Counter(labels[row["y"]] for row in rows)) for split, rows in splits.items()}
    print(f"[{args.task}] {args.model} max_length={max_length} {counts}")

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    datasets = {split: tokenize(tokenizer, rows, max_length) for split, rows in splits.items()}
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=len(labels), id2label=dict(enumerate(labels)), label2id={v: k for k, v in enumerate(labels)},
    )

    train_counts = Counter(row["y"] for row in splits["train"])
    weights = torch.tensor([len(splits["train"]) / (len(labels) * max(1, train_counts[k])) for k in range(len(labels))],
                           dtype=torch.float)
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights)

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
        for input_ids, attention_mask, y in train_loader:
            optimizer.zero_grad()
            loss = loss_fn(model(input_ids=input_ids, attention_mask=attention_mask).logits, y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            losses.append(loss.item())
        y_true, y_pred, _ = predict(model, val_loader)
        val = scores(y_true, y_pred, labels)
        history.append({"epoch": epoch, "train_loss": round(float(np.mean(losses)), 4),
                        "val_macro_f1": val["macro"]["f1"], "val_accuracy": val["accuracy"]})
        print(f"[epoch {epoch}] loss={history[-1]['train_loss']} val_macro_f1={val['macro']['f1']} "
              f"val_acc={val['accuracy']} ({time.time() - started:.0f}s)")
        if val["macro"]["f1"] > best_f1:
            best_f1, best_epoch = val["macro"]["f1"], epoch
            model.save_pretrained(output_dir)
            tokenizer.save_pretrained(output_dir)

    model = AutoModelForSequenceClassification.from_pretrained(output_dir)
    val_scores = scores(*predict(model, val_loader)[:2], labels)
    y_true, y_pred, probs = predict(model, test_loader)
    test_scores = scores(y_true, y_pred, labels)
    by_group = {}
    for group in sorted({row["group"] for row in splits["test"]}):
        idx = [i for i, row in enumerate(splits["test"]) if row["group"] == group]
        by_group[group] = {"n": len(idx), "accuracy": round(float(np.mean([y_true[i] == y_pred[i] for i in idx])), 4)}
    original = [i for i, row in enumerate(splits["test"]) if not row.get("extra_source")]
    test_original = (scores([y_true[i] for i in original], [y_pred[i] for i in original], labels)
                     if args.extra_jsonl else None)
    by_source: dict[str, dict] = {}
    for source in sorted({row.get("source_dataset") or "unknown" for row in splits["test"]}):
        idx = [i for i, row in enumerate(splits["test"]) if (row.get("source_dataset") or "unknown") == source]
        by_source[source] = {"n": len(idx), "accuracy": round(float(np.mean([y_true[i] == y_pred[i] for i in idx])), 4)}
    errors = [{"sample_id": row["sample_id"], "true": labels[y_true[i]], "pred": labels[y_pred[i]],
               "confidence": round(max(probs[i]), 4)}
              for i, row in enumerate(splits["test"]) if y_true[i] != y_pred[i]]

    metrics_path.write_text(json.dumps({
        "task": args.task, "model": args.model, "labels": labels,
        "saved_model": str(output_dir.relative_to(ROOT)).replace("\\", "/"),
        "hyperparameters": {"epochs": args.epochs, "batch_size": args.batch_size, "max_length": max_length,
                            "lr": args.lr, "seed": args.seed, "class_weights": [round(float(w), 4) for w in weights],
                            "device": "cpu"},
        "label_counts": counts, "best_epoch": best_epoch, "history": history,
        "validation": val_scores, "test": test_scores, "test_original_rows": test_original,
        "extra_sources": [str(p).replace("\\", "/") for p in args.extra_jsonl], "test_by_source": by_source,
        "test_by_group": by_group, "test_errors": errors,
        "unlabelled_categories": ["brand_impersonation", "malware", "browser_abuse", "other_scam"] if args.task == "category" else [],
        "notes": ("Each scam class comes from a single source dataset (phishing: Phish360 emails, financial_scam: "
                  "DIFrauD job scams), so the model can partly learn source style; data_theft has 10 samples."
                  if args.task == "category" else
                  "Fakeddit labels are provisional (derived from the subreddit); text-only on post titles."),
        "training_seconds": round(time.time() - started, 1),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")
    plot_confusion(test_scores["confusion_matrix"]["rows_true_cols_pred"], labels,
                   f"{args.task} test (n={len(y_true)}, macro F1={test_scores['macro']['f1']})", confusion_path)
    print(f"[val]  acc={val_scores['accuracy']} macro_f1={val_scores['macro']['f1']}")
    print(f"[test] acc={test_scores['accuracy']} macro_f1={test_scores['macro']['f1']} per_class="
          f"{json.dumps({k: v['f1'] for k, v in test_scores['per_class'].items()})}")
    print(f"[test] confusion {test_scores['confusion_matrix']['rows_true_cols_pred']}")
    if test_original:
        print(f"[test original rows] acc={test_original['accuracy']} macro_f1={test_original['macro']['f1']} per_class="
              f"{json.dumps({k: v['f1'] for k, v in test_original['per_class'].items()})}")
    print(f"Saved model to {output_dir}")


if __name__ == "__main__":
    main()
