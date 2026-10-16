"""Part 6A text models: Colab bundle, model import, local smoke training, TF-IDF baseline.

Part 6: XLM-R content classification (6A, page level).
Thin CLI wrapper - all logic lives in ``c2_analyzer.nlp``.

    python scripts/train_xlmr.py export-bundle --version v0.3   # -> data/tmp/xlmr_bundle_v0.3.zip
    python scripts/train_xlmr.py import-model --zip xlmr_v0.3.zip --version v0.3 [--force]
    python scripts/train_xlmr.py train --version v0.3 --smoke   # CPU pipeline check (tiny model)
    python scripts/train_xlmr.py baseline --version v0.3        # TF-IDF + LogReg baseline
    python scripts/train_xlmr.py token-stats --version v0.3     # truncation at 512 per language

Real fine-tuning runs on Colab (notebooks/04_xlmr_finetune_colab.ipynb).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.nlp.common import XlmrConfig
from c2_analyzer.nlp.dataset import build_examples


def _mb(n: int) -> str:
    return f"{n / 1024 / 1024:.2f} MB" if n >= 1024 * 1024 else f"{n / 1024:.1f} KB"


def cmd_export(args, config: XlmrConfig) -> int:
    from c2_analyzer.nlp.bundle import export_bundle

    path, members = export_bundle(args.version, config)
    for name, size in members:
        print(f"  {_mb(size):>10}  {name}")
    print(f"bundle: {path} ({_mb(path.stat().st_size)} zipped, {len(members)} files)")
    print(f"base model: {config.model_name} (from .env XLMR_MODEL_NAME)")
    return 0


def cmd_import(args, config: XlmrConfig) -> int:
    from c2_analyzer.nlp.bundle import ImportRefused, import_model

    try:
        result = import_model(Path(args.zip), args.version, config, force=args.force)
    except ImportRefused as error:
        print(f"IMPORT REFUSED: {error}", file=sys.stderr)
        return 1
    print(f"imported into {result['target']}")
    print(f"final model = seed {result['final_seed']}; seeds {', '.join(result['seeds'])}")
    print(
        f"seed weights downloaded: {', '.join(result['seed_weights']) or 'none (predictions only)'}"
    )
    print(f"next: python scripts/evaluate_xlmr.py --version {args.version}")
    return 0


def cmd_train(args, config: XlmrConfig) -> int:
    from c2_analyzer.nlp.dataset import export_examples
    from c2_analyzer.nlp.model import build_tiny_model_dir
    from c2_analyzer.nlp.train import train_all

    data = build_examples(args.version)
    model_name = args.model_name or config.model_name
    if args.smoke:
        out = config.smoke_dir(args.version)
        examples_dir = out / "examples"
        export_examples(data, examples_dir, model_name=model_name)
        if not args.model_name:
            model_name = str(
                build_tiny_model_dir(
                    out / "tiny_model", [row["text"] for row in data.rows("train")], data.labels
                )
            )
            print("smoke: tiny random-init XLM-R (2 layers, built in code, no download)")
        model_root = out / "models"
    else:
        print(
            "WARNING: real fine-tuning on this machine's CPU takes many hours - use the "
            "Colab notebook (export-bundle) unless this is deliberate.",
            file=sys.stderr,
        )
        examples_dir = config.bundle_dir / f"xlmr_examples_{args.version}"
        export_examples(data, examples_dir, model_name=model_name)
        model_root = config.models_dir(args.version)
    card = train_all(
        examples_dir, model_root, config.training_config(), model_name, args.seeds, args.smoke
    )
    final_seed = card["selection"]["final_seed"]
    print(f"model card: {model_root / 'model_card.json'} (final seed {final_seed})")
    if args.smoke:
        print("smoke run OK - the numbers mean nothing (random tiny model, 1 step)")
    return 0


def cmd_baseline(args, config: XlmrConfig) -> int:
    from c2_analyzer.nlp.text_baseline import train_text_baseline

    results = train_text_baseline(args.version, config, figures=not args.no_figures)
    model = results["models"][results["best_model"]]
    test = model["test"]
    print(
        f"\nTF-IDF + LogReg ({args.version}): C={model['params']['C']:g}, "
        f"CV macro-F1 {model['cv']['mean']['macro_f1']:.3f} ± {model['cv']['std']['macro_f1']:.3f}"
    )
    print(
        f"TEST (once, n={test['n']}): macro-P {test['macro_precision']:.3f}  macro-R "
        f"{test['macro_recall']:.3f}  macro-F1 {test['macro_f1']:.3f}  accuracy "
        f"{test['accuracy']:.3f}  benign FPR {100 * test['benign_fpr']:.1f} %"
    )
    for label, row in test["per_class"].items():
        print(
            f"  {label:<18} P {row['precision']:.3f}  R {row['recall']:.3f}  "
            f"F1 {row['f1']:.3f}  n {row['support']}"
        )
    print("per language (test):")
    for language, row in model["per_language"].items():
        if row["n"]:
            flag = "  (small n)" if row["small_n"] else ""
            print(f"  {language:<6} n {row['n']:>3}  macro-F1 {row['macro_f1']:.3f}{flag}")
    print(f"reports: {config.baseline_reports_dir(args.version)}")
    return 0


def cmd_token_stats(args, config: XlmrConfig) -> int:
    from c2_analyzer.nlp.tokenizer import load_tokenizer, render_token_stats_md, token_length_stats
    from c2_analyzer.utils.io import atomic_write_text, write_json

    data = build_examples(args.version)
    name = args.tokenizer or config.model_name
    tokenizer = load_tokenizer(name)
    stats = token_length_stats(tokenizer, data.examples, config.max_length)
    stats["tokenizer"] = name
    out = config.reports_dir(args.version)
    write_json(stats, out / "token_stats.json")
    markdown = render_token_stats_md(stats, f"XLM-R token lengths of page_text - {args.version}")
    atomic_write_text(markdown, out / "token_stats.md")
    print(markdown)
    print(f"written: {out / 'token_stats.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export-bundle", help="zip examples + config + training code for Colab")
    export.add_argument("--version", required=True)
    imp = sub.add_parser("import-model", help="verify + unpack the zip downloaded from Colab")
    imp.add_argument("--zip", required=True)
    imp.add_argument("--version", required=True)
    imp.add_argument("--force", action="store_true", help="replace an existing model")
    train = sub.add_parser("train", help="train locally (use --smoke on a laptop)")
    train.add_argument("--version", required=True)
    train.add_argument("--smoke", action="store_true", help="tiny subset, 1 step, tiny model")
    train.add_argument("--seeds", type=int, nargs="+", default=None)
    train.add_argument("--model-name", default=None, help="hub name or local folder")
    baseline = sub.add_parser("baseline", help="TF-IDF char 2-5 + LogReg text baseline")
    baseline.add_argument("--version", required=True)
    baseline.add_argument("--no-figures", action="store_true")
    stats = sub.add_parser("token-stats", help="token lengths / truncation per language")
    stats.add_argument("--version", required=True)
    stats.add_argument("--tokenizer", default=None, help="default: XLMR_MODEL_NAME")
    args = parser.parse_args(argv)
    config = XlmrConfig.load()
    handlers = {
        "export-bundle": cmd_export,
        "import-model": cmd_import,
        "train": cmd_train,
        "baseline": cmd_baseline,
        "token-stats": cmd_token_stats,
    }
    return handlers[args.command](args, config)


if __name__ == "__main__":
    sys.exit(main())
