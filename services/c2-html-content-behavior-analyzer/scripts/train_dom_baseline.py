"""Train and evaluate the DOM baselines (Part 4): split, train, evaluate, all, predict.

Part 4: DOM baseline classifier ("Baseline 1": LogReg / RandomForest / XGBoost).

Why: a thin command-line wrapper; all logic is in c2_analyzer.dataset.splits
and c2_analyzer.classifiers.dom_baseline.

- ``split``    makes the shared train/val/test split + CV folds of a frozen
               version (data/splits/<version>/) - used by EVERY later part.
- ``train``    grid search on grouped CV (train+val), refit, save the models.
- ``evaluate`` the one evaluation on test + feature importance + reports.
- ``all``      split (only if missing) -> train -> evaluate. One command for
               every dataset version: ``all --version v0.2`` needs no changes.
- ``predict``  probabilities of every model for one page + the top 5 SHAP
               contributions (XGBoost) in plain English.
Nothing here runs JavaScript or downloads anything.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

from c2_analyzer.classifiers.dom_baseline.common import (
    BaselineConfig,
    load_bundles,
    model_dir,
    parse_models,
    report_dir,
)
from c2_analyzer.classifiers.dom_baseline.data import prepare_dataset
from c2_analyzer.classifiers.dom_baseline.evaluate import confusion_text
from c2_analyzer.classifiers.dom_baseline.predict import PredictionError, predict_features
from c2_analyzer.classifiers.dom_baseline.report import StaleModelError, run_report, shap_top_text
from c2_analyzer.dataset.manifest import list_versions, manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.splits import SPLITS, SplitError, create_split, split_paths, splits_root
from c2_analyzer.dom.dictionary import dictionary_hash
from c2_analyzer.dom.pipeline import dom_features_for_html
from c2_analyzer.preprocessing.loader import from_file

EXAMPLES = """examples:
  python scripts/train_dom_baseline.py all --version v0.1
  python scripts/train_dom_baseline.py split --version v0.1 [--force]
  python scripts/train_dom_baseline.py train --version v0.1 --models logreg,rf,xgb
  python scripts/train_dom_baseline.py evaluate --version v0.1
  python scripts/train_dom_baseline.py predict --sample-id c2_phishing_000081
  python scripts/train_dom_baseline.py predict --file page.html --url https://example.com/login
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    parser.add_argument("--splits-dir", type=Path, help="default data/splits")
    parser.add_argument(
        "--features-dir", type=Path, help="default data/processed/dom_features/<version>"
    )
    parser.add_argument("--models-dir", type=Path, help="default models/dom_baseline")
    parser.add_argument("--reports-dir", type=Path, help="default reports/dom_baseline")
    parser.add_argument("--quiet", action="store_true", help="no progress bars")
    commands = parser.add_subparsers(dest="command", required=True)

    split = commands.add_parser("split", help="shared train/val/test split + CV folds")
    split.add_argument("--version", required=True, help="e.g. v0.1 (data/metadata/manifests/)")
    split.add_argument("--force", action="store_true", help="replace an existing split")

    train = commands.add_parser("train", help="grid search on CV, refit on train+val, save")
    train.add_argument("--version", required=True)
    train.add_argument("--models", help="comma list: logreg,rf,xgb (default all)")

    evaluate = commands.add_parser("evaluate", help="test evaluation + importance + reports")
    evaluate.add_argument("--version", required=True)

    run_all = commands.add_parser("all", help="split (if missing) -> train -> evaluate")
    run_all.add_argument("--version", required=True)
    run_all.add_argument("--models", help="comma list: logreg,rf,xgb (default all)")

    predict = commands.add_parser("predict", help="probabilities + top 5 SHAP for one page")
    source = predict.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample-id", help="a sample of the dataset version")
    source.add_argument("--file", type=Path, help="any local .html file")
    predict.add_argument("--url", help="the page's address (for --file; never fetched)")
    predict.add_argument("--version", help="models of this version (default: newest trained)")
    predict.add_argument("--json", action="store_true", help="print the DomPrediction JSON")
    return parser


def _config(args: argparse.Namespace) -> BaselineConfig:
    config = BaselineConfig.load()
    changes = {}
    if args.models_dir:
        changes["models_dir"] = args.models_dir
    if args.reports_dir:
        changes["reports_dir"] = args.reports_dir
    return replace(config, **changes) if changes else config


def _split_root(args: argparse.Namespace) -> Path:
    return args.splits_dir or splits_root()


# ---- split -----------------------------------------------------------------------------------


def print_split(info: dict) -> None:
    labels = info["included_classes"]
    print(
        f"Split of {info['version']} (seed {info['seed']}, stratified by "
        f"{' x '.join(info['stratify_by'])}, grouped by {info['group_by']}):"
    )
    print(
        f"{'split':<8}{'pages':>7}{'share':>8}{'target':>8}" + "".join(f"{x:>18}" for x in labels)
    )
    for name in SPLITS:
        per_label = info["counts_per_label"].get(name, {})
        print(
            f"{name:<8}{info['counts'][name]:>7}{100 * info['actual_ratios'][name]:>7.1f}%"
            f"{100 * info['target_ratios'][name]:>7.0f}%"
            + "".join(f"{per_label.get(label, 0):>18}" for label in labels)
        )
    print(
        f"largest ratio deviation {100 * info['max_ratio_difference']:.2f} points; "
        f"clusters in two splits: {info['clusters_in_two_splits']}; "
        f"{info['cv_folds']} grouped CV folds over train+val"
    )
    for language, parts in info["language_placement"].items():
        print(f"  {language}: " + ", ".join(f"{name} {n}" for name, n in parts.items()))
    if info["excluded_classes"]:
        excluded = ", ".join(f"{k} ({v} pages)" for k, v in info["excluded_classes"].items())
        print(
            f"EXCLUDED (< {info['min_samples_per_class']} pages): {excluded} -> PILOT run "
            f"with {len(labels)} classes"
        )


def cmd_split(args: argparse.Namespace, store: MetadataStore) -> int:
    info = create_split(
        args.version, manifests_dir(store), store.raw_dir, _split_root(args), force=args.force
    )
    print_split(info)
    print(f"\nSaved {split_paths(args.version, _split_root(args))[0].parent}")
    return 0


# ---- train / evaluate --------------------------------------------------------------------------


def _dataset(args: argparse.Namespace, config: BaselineConfig, store: MetadataStore):
    return prepare_dataset(
        args.version,
        config.correlation_threshold,
        features_dir=args.features_dir,
        splits_root=_split_root(args),
        manifests=manifests_dir(store),
    )


def print_dataset(dataset) -> None:
    print(
        f"DOM features {dataset.feature_set_version}: {len(dataset.all_features)} -> "
        f"{len(dataset.features)} used; classes {dataset.labels}"
        + (" (PILOT)" if dataset.pilot else "")
    )
    for item in dataset.dropped:
        print(f"  dropped {item['feature']:<36} {item['reason']:<11} {item['detail']}")


def cmd_train(args: argparse.Namespace, store: MetadataStore, dataset=None) -> int:
    config = _config(args)
    dataset = dataset or _dataset(args, config, store)
    print_dataset(dataset)
    from c2_analyzer.classifiers.dom_baseline.train import train_all  # imports xgboost

    started = time.perf_counter()
    bundles = train_all(dataset, config, parse_models(args.models), show_progress=not args.quiet)
    print(f"\nCV on train+val ({dataset.split_info['cv_folds']} grouped folds), best grid point:")
    for bundle in bundles.values():
        mean, std = bundle["cv"]["mean"], bundle["cv"]["std"]
        params = ", ".join(f"{k}={v}" for k, v in bundle["params"].items())
        print(
            f"  {bundle['display_name']:<20} macro-F1 "
            f"{mean['macro_f1']:.3f} +/- {std['macro_f1']:.3f}"
            f"  ({len(bundle['grid'])} points, {bundle['training_seconds']} s)  {params}"
        )
    print(
        f"Saved models to {model_dir(config, dataset.version)} "
        f"in {time.perf_counter() - started:.1f} s"
    )
    return 0


def _metric(value) -> str:
    return "   —  " if value is None else f"{value:6.3f}"


def cmd_evaluate(args: argparse.Namespace, store: MetadataStore, dataset=None) -> int:
    config = _config(args)
    dataset = dataset or _dataset(args, config, store)
    bundles = load_bundles(config, dataset.version)
    results = run_report(dataset, bundles, config)
    models, labels, best = results["models"], results["classes"], results["best_model"]

    print(f"\nBaseline 1 - DOM only ({dataset.version}{', PILOT' if results['pilot'] else ''}):")
    print(
        f"{'model':<21}{'CV macro-F1':>15}{'test mF1':>9}{'w-F1':>8}{'acc':>8}{'bal.acc':>8}"
        f"{'AUC':>8}{'benignFPR':>10}"
    )
    for name, model in models.items():
        cv, test = model["cv"], model["test"]
        fpr = test["benign_fpr"]
        print(
            f"{model['display_name'] + (' *' if name == best else ''):<21}"
            f"{cv['mean']['macro_f1']:>8.3f} +/- {cv['std']['macro_f1']:.3f}"
            f"{_metric(test['macro_f1']):>9}{_metric(test['weighted_f1']):>8}"
            f"{_metric(test['accuracy']):>8}{_metric(test['balanced_accuracy']):>8}"
            f"{_metric(test['roc_auc_ovr_macro']):>8}"
            f"{'—' if fpr is None else f'{100 * fpr:.1f}%':>10}"
        )
    print(
        f"* best by CV macro-F1 (selected before test). Benign FPR target <= "
        f"{100 * results['benign_fpr_target']:.0f}%."
    )
    for model in models.values():
        flagged = model["benign_false_positives"]
        print(f"  benign FP {model['display_name']}: {', '.join(flagged) if flagged else 'none'}")

    print(f"\nConfusion matrix - {models[best]['display_name']} (test, rows = true):")
    print(confusion_text(models[best]["test"]["confusion_matrix"], labels))
    print("\nPer language (best model, test):")
    for language, v in models[best]["per_language"].items():
        note = "  (small n)" if v["small_n"] else ""
        print(f"  {language:<8} n={v['n']:<4} accuracy {v['accuracy']:.3f}{note}")
    shap_lines = shap_top_text(results, 10)
    if shap_lines:
        print("\nTop 10 SHAP features (XGBoost, mean |SHAP| on test - indicative on a pilot set):")
        print("\n".join(f"  {line}" for line in shap_lines))
    print(
        "\nMisclassified test pages: "
        + ", ".join(f"{m['display_name']} {m['misclassified']}" for m in models.values())
        + f" (of {results['split']['counts']['test']})"
    )
    folder = report_dir(config, dataset.version)
    print(
        f"\nReport: {folder / 'results.md'}\n"
        f"Model card: {model_dir(config, dataset.version) / 'model_card.json'}"
    )
    return 0


def cmd_all(args: argparse.Namespace, store: MetadataStore) -> int:
    csv_path, json_path, _ = split_paths(args.version, _split_root(args))
    if csv_path.is_file() and json_path.is_file():
        print(f"Using the existing split {csv_path.parent} (split --force to replace it)")
        print_split(json.loads(json_path.read_text(encoding="utf-8")))
    else:
        args.force = False
        cmd_split(args, store)
    print()
    config = _config(args)
    dataset = _dataset(args, config, store)
    cmd_train(args, store, dataset)
    return cmd_evaluate(args, store, dataset)


# ---- predict -----------------------------------------------------------------------------------


def _trained_version(config: BaselineConfig, store: MetadataStore) -> str:
    for version in reversed(list_versions(manifests_dir(store))):
        if load_bundles(config, version):
            return version
    raise FileNotFoundError(
        "no trained DOM baseline - run: train_dom_baseline.py all --version v0.1"
    )


def cmd_predict(args: argparse.Namespace, store: MetadataStore) -> int:
    config = _config(args)
    version = args.version or _trained_version(config, store)
    if args.sample_id:
        from c2_analyzer.api.dev_data import DevDataset, NotFoundError

        dataset = DevDataset.from_settings()
        dataset.baseline_models, dataset.baseline_reports = config.models_dir, config.reports_dir
        dataset.splits = _split_root(args)
        try:
            bundles, card = dataset.baseline_bundles(version)
            text, source = dataset.dom_features(version, args.sample_id)
        except NotFoundError as error:
            raise FileNotFoundError(str(error)) from None
        from c2_analyzer.schemas.dom import DomResult

        features = DomResult.model_validate_json(text).features
        split = dataset.split_of(version, args.sample_id)
        true_label = dataset._row(version, args.sample_id)["label"]
    else:
        raw = from_file(args.file, page_url=args.url)
        features = dom_features_for_html(raw.html, args.url).features
        bundles = load_bundles(config, version)
        card_path = model_dir(config, version) / "model_card.json"
        card = json.loads(card_path.read_text("utf-8")) if card_path.is_file() else {}
        source, split, true_label = "computed", None, None
    prediction = predict_features(
        features,
        bundles,
        version=version,
        dictionary_hash=dictionary_hash(),
        excluded_classes=card.get("excluded_classes", {}),
        explain="xgboost",
        top=config.contributions,
        sample_id=args.sample_id,
    )
    prediction.true_label, prediction.split, prediction.features_source = true_label, split, source
    if args.json:
        print(prediction.model_dump_json(indent=2))
        return 0

    name = args.sample_id or str(args.file)
    extra = f" (true: {true_label}, split: {split})" if true_label else ""
    pilot = (
        f"   PILOT model ({version}, {len(prediction.classes)} classes)" if prediction.pilot else ""
    )
    print(f"{name}{extra}{pilot}")
    print(
        f"{'model':<22}" + "".join(f"{label:>18}" for label in prediction.classes) + "   predicted"
    )
    for answer in prediction.models:
        star = " *" if answer.model == prediction.best_model else ""
        print(
            f"{answer.display_name + star:<22}"
            + "".join(f"{answer.probabilities[label]:>18.3f}" for label in prediction.classes)
            + f"   {answer.predicted}"
        )
    print(
        f"* best model by CV macro-F1 -> {prediction.predicted} "
        f"({prediction.probabilities[prediction.predicted]:.3f})"
    )
    explained = next(a for a in prediction.models if a.model == prediction.explained_model)
    print(
        f"\nTop {len(prediction.contributions)} SHAP contributions "
        f"({explained.display_name}, class {explained.predicted}):"
    )
    for item in prediction.contributions:
        print(f"  {item.contribution:+.3f}  {item.text}")
    if prediction.excluded_classes:
        print(f"\nNote: cannot predict {', '.join(prediction.excluded_classes)} (not trained).")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Sinhala/Tamil never crash the console
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    store = MetadataStore(args.metadata, args.raw_dir)
    commands = {
        "split": cmd_split,
        "train": cmd_train,
        "evaluate": cmd_evaluate,
        "all": cmd_all,
        "predict": cmd_predict,
    }
    try:
        return commands[args.command](args, store)
    except (
        ValueError,
        KeyError,
        FileNotFoundError,
        FileExistsError,
        SplitError,
        StaleModelError,
        PredictionError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
