"""Train and validate the single-class YOLO logo detector baseline.

Requires ``scripts/prepare_logo_yolo_dataset.py`` (data/processed/logo_yolo/data.yaml).

Checklist: Configure YOLO model, Train logo detector baseline, Validate logo detector.

Writes:
  models/logo_detector/runs/<run>/            — Ultralytics run (weights, curves)
  models/logo_detector/<run>_best.pt          — best weights
  data/statistics/logo_detector_training.json — config + val/test metrics (overall, dom, synthetic)

Usage:
  python scripts/train_logo_detector.py
  python scripts/train_logo_detector.py --epochs 40 --imgsz 640 --batch 8
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import _bootstrap

try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    pass

from prepare_logo_yolo_dataset import MANIFEST, ROOT, YOLO_DIR, mark_checklist, read_jsonl

MODELS_DIR = ROOT / "models" / "logo_detector"
TRAINING = ROOT / "data" / "statistics" / "logo_detector_training.json"


def subset_yaml(split: str, origin: str) -> Path:
    """data.yaml whose val list holds only one origin (dom / synthetic) of a split."""
    images = [ROOT / row["image"] for row in read_jsonl(MANIFEST) if row["split"] == split and row["origin"] == origin]
    listing = YOLO_DIR / f"{split}_{origin}.txt"
    listing.write_text("\n".join(path.as_posix() for path in images) + "\n", encoding="utf-8")
    config = YOLO_DIR / f"data_{split}_{origin}.yaml"
    config.write_text(f"path: {YOLO_DIR.as_posix()}\ntrain: images/train\nval: {listing.as_posix()}\nnames:\n  0: logo\n",
                      encoding="utf-8")
    return config


def box_metrics(result) -> dict:
    box = result.box
    return {"precision": round(float(box.mp), 4), "recall": round(float(box.mr), 4),
            "mAP50": round(float(box.map50), 4), "mAP50_95": round(float(box.map), 4)}


def main() -> None:
    _bootstrap.setup()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--weights", default="yolo11n.pt")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--imgsz", type=int, default=640)
    parser.add_argument("--batch", type=int, default=8)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--resume", action="store_true", help="Continue an interrupted run from its last.pt")
    args = parser.parse_args()

    from ultralytics import YOLO

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    run = f"{Path(args.weights).stem}_logo_baseline"
    config = {
        "weights": args.weights, "task": "detect", "classes": ["logo"], "data": "data/processed/logo_yolo/data.yaml",
        "epochs": args.epochs, "imgsz": args.imgsz, "batch": args.batch, "patience": args.patience,
        "device": "cpu", "workers": 0, "seed": args.seed, "optimizer": "auto",
        "fliplr": 0.0, "mosaic": 1.0, "close_mosaic": 5,
        "note": "fliplr disabled: mirrored logos/text are not realistic",
    }
    mark_checklist("Configure YOLO model")

    run_dir = MODELS_DIR / "runs" / run
    started = time.time()
    if args.resume:
        YOLO(str(run_dir / "weights" / "last.pt")).train(resume=True)
    else:
        YOLO(str(MODELS_DIR / args.weights)).train(
            data=str(YOLO_DIR / "data.yaml"), epochs=args.epochs, imgsz=args.imgsz, batch=args.batch,
            patience=args.patience, device="cpu", workers=0, seed=args.seed, fliplr=0.0, close_mosaic=5,
            project=str(MODELS_DIR / "runs"), name=run, exist_ok=True, plots=True, verbose=False,
        )
    train_seconds = round(time.time() - started, 1)
    config["resumed"] = args.resume
    epochs_log = (run_dir / "results.csv").read_text(encoding="utf-8").splitlines()
    if len(epochs_log) > 1:
        train_seconds = round(float(epochs_log[-1].split(",")[1]), 1)
    best = MODELS_DIR / f"{run}_best.pt"
    shutil.copy2(run_dir / "weights" / "best.pt", best)
    mark_checklist("Train logo detector baseline")

    detector = YOLO(str(best))
    common = {"imgsz": args.imgsz, "batch": args.batch, "device": "cpu", "workers": 0, "plots": False, "verbose": False,
              "project": str(MODELS_DIR / "runs"), "exist_ok": True}
    metrics = {
        "val": box_metrics(detector.val(data=str(YOLO_DIR / "data.yaml"), split="val", name=f"{run}_val", **common)),
        "test": box_metrics(detector.val(data=str(YOLO_DIR / "data.yaml"), split="test", name=f"{run}_test", **common)),
    }
    for split in ("val", "test"):
        for origin in ("dom", "synthetic"):
            metrics[f"{split}_{origin}"] = box_metrics(
                detector.val(data=str(subset_yaml(split, origin)), split="val", name=f"{run}_{split}_{origin}", **common))
    mark_checklist("Validate logo detector")

    TRAINING.write_text(json.dumps({
        "config": config,
        "best_weights": str(best.relative_to(ROOT)).replace("\\", "/"),
        "run_dir": str(run_dir.relative_to(ROOT)).replace("\\", "/"),
        "train_seconds": train_seconds,
        "metrics": metrics,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, indent=2), encoding="utf-8")
    for name, values in metrics.items():
        print(f"[{name:14}] {values}")
    print(f"Saved {best}")


if __name__ == "__main__":
    main()
