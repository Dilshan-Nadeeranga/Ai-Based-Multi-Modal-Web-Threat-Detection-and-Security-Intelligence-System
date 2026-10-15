"""Behavioral intent mapping (Part 8): a dataset version, one page, the vector, the baseline.

Part 8: Behavioral intent mapping (sources -> sinks).

Why: a thin command-line wrapper; all logic is in c2_analyzer.behavior.
- ``run``            maps every sample of a frozen dataset version (from the stored
                     Part 2 + Part 7 JSON; Part 2 / Part 7 are run and saved for any
                     missing sample), writes behavior_features.csv and the report.
- ``one``            findings of a single page with their evidence chains (text).
- ``describe``       the intent vector and the pattern catalogue.
- ``train-baseline`` the behavior-only baseline (js_features + behavior_features)
                     with Part 4's code and protocol on the shared split, then the
                     DOM-only vs behavior-only comparison.
Nothing here runs JavaScript or downloads anything.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from c2_analyzer.behavior.batch import export_json, output_dir, run_version
from c2_analyzer.behavior.pipeline import map_behavior
from c2_analyzer.behavior.report import (
    describe_dictionary,
    describe_result,
    summarize,
    write_report,
)
from c2_analyzer.config import get_labels
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.js_analyzer.pipeline import analyze_js
from c2_analyzer.preprocessing.loader import from_file, from_sample
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.utils.hashing import sha256_file
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/map_behavior.py run --version v0.3
  python scripts/map_behavior.py run --version v0.3 --force --workers 4
  python scripts/map_behavior.py one --sample-id c2_phishing_000081
  python scripts/map_behavior.py one --file page.html --url https://example.com/login [--json]
  python scripts/map_behavior.py describe [--markdown]
  python scripts/map_behavior.py train-baseline --version v0.3
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    parser.add_argument("--out-dir", type=Path, help="default data/processed/behavior/<version>")
    parser.add_argument("--reports-dir", type=Path, help="default reports/behavior")
    parser.add_argument("--parsed-dir", type=Path, help="Part 2 JSON folder")
    parser.add_argument("--js-dir", type=Path, help="Part 7 JSON folder")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="map every sample of a frozen dataset version")
    run.add_argument("--version", required=True, help="e.g. v0.3 (see data/metadata/manifests/)")
    run.add_argument("--label", choices=get_labels(), help="only this label (CSV keeps all)")
    run.add_argument("--limit", type=int, help="process at most N samples")
    run.add_argument("--workers", type=int, help="parallel processes (default from config: 4)")
    run.add_argument("--force", action="store_true", help="redo samples that are already done")

    one = commands.add_parser("one", help="findings + evidence chains of one page (text)")
    source = one.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample-id", help="a registered sample")
    source.add_argument("--file", type=Path, help="any local .html file")
    one.add_argument("--url", help="the page's address (for --file; never fetched)")
    one.add_argument("--version", help="dataset version to record in the output")
    one.add_argument("--json", action="store_true", help="print the full BehaviorResult JSON")
    one.add_argument("--save", action="store_true", help="also save the JSON (adhoc folder)")

    describe = commands.add_parser("describe", help="print the intent vector + patterns")
    describe.add_argument("--markdown", action="store_true", help="as Markdown tables")

    baseline = commands.add_parser(
        "train-baseline", help="behavior-only baseline (Part 4 protocol) + DOM comparison"
    )
    baseline.add_argument("--version", required=True)
    baseline.add_argument("--models", help="comma list: logreg,rf,xgb (default all)")
    baseline.add_argument("--quiet", action="store_true", help="no progress bars")
    return parser


def cmd_run(args: argparse.Namespace, store: MetadataStore) -> int:
    results, seconds, rows, csv_path = run_version(
        store,
        args.version,
        label=args.label,
        limit=args.limit,
        workers=args.workers,
        force=args.force,
        out_dir=args.out_dir,
        parsed_dir=args.parsed_dir,
        js_dir=args.js_dir,
    )
    filters = {"label": args.label, "limit": args.limit, "force": args.force}
    summary = summarize(rows, results, args.version, seconds, filters)
    paths = write_report(summary, args.reports_dir)
    counts, timing = summary["counts"], summary["timing"]
    print(
        f"Dataset {args.version}: {counts['run_total']} page(s) - processed {counts['processed']}, "
        f"unchanged {counts['skipped_unchanged']}, failed {counts['failed']} (Part 2 run for "
        f"{counts['part2_processed_now']}, Part 7 for {counts['part7_processed_now']}); rows in "
        f"CSV: {counts['rows_in_csv']}; truncated {counts['truncated']}"
    )
    print(
        f"Intent vector {summary['feature_set_version']} ({summary['feature_count']} features); "
        f"time per page avg {timing['avg_ms']} ms, median {timing['median_ms']} ms, p95 "
        f"{timing['p95_ms']} ms, max {timing['max_ms']} ms; wall {timing['wall_seconds']} s"
    )
    for failure in summary["failures"][:20]:
        print(f"  FAILED {failure['sample_id']}: {failure['error']}")

    labels, per_label, names = summary["labels"], summary["per_label"], summary["pattern_names"]
    width = max(len(n) for n in names.values()) + 2
    print("\n% of pages with each pattern (any severity):")
    print(f"{'pattern':<{width}}" + "".join(f"{label[:16]:>18}" for label in labels))
    print(f"{'(pages)':<{width}}" + "".join(f"{per_label[lab]['pages']:>18}" for lab in labels))
    for pattern, name in names.items():
        print(
            f"{name:<{width}}"
            + "".join(f"{per_label[lab]['patterns'][pattern]['pct']:>17.1f}%" for lab in labels)
        )
    print("\n% of pages by highest severity:")
    for severity in ("critical", "high", "medium", "low", "none"):
        print(
            f"{severity:<{width}}"
            + "".join(f"{per_label[lab]['max_severity_pct'][severity]:>17.1f}%" for lab in labels)
        )
    print(
        f"{'mean risk score':<{width}}"
        + "".join(f"{per_label[lab]['risk_score_mean']:>18.1f}" for lab in labels)
    )
    print(
        f"{'% with a flow':<{width}}"
        + "".join(f"{per_label[lab]['flows']['pages_with_flow']:>17.1f}%" for lab in labels)
    )
    check = summary["benign_false_positive_check"]
    print(
        f"\nFalse-positive check: {check['pages_with_critical_or_high']} of "
        f"{check['benign_pages']} benign pages have a critical / high finding"
        + (": " + ", ".join(p["sample_id"] for p in check["pages"]) if check["pages"] else "")
    )
    print(f"\nCSV:     {csv_path}")
    print("Report:  " + "\n         ".join(str(path) for path in paths))
    return 1 if counts["failed"] else 0


def cmd_one(args: argparse.Namespace, store: MetadataStore) -> int:
    if args.sample_id:
        raw = from_sample(store, args.sample_id, dataset_version=args.version)
        name = args.sample_id
    else:
        raw = from_file(args.file, page_url=args.url)
        name = sha256_file(args.file)[:16]  # ad-hoc pages have no sample id
    page = preprocess(raw)
    result = map_behavior(page, analyze_js(page))
    if args.json:
        print(result.model_dump_json(indent=1))
    else:
        print(describe_result(result, label=raw.label))
    if args.save:
        path = export_json(result, (args.out_dir or output_dir(args.version)) / f"{name}.json")
        print(f"\nSaved {path}")
    return 0


def cmd_train_baseline(args: argparse.Namespace, store: MetadataStore) -> int:
    from c2_analyzer.behavior.baseline import (
        BEHAVIOR_SOURCE,
        compare,
        comparison_markdown,
        write_comparison,
    )
    from c2_analyzer.classifiers.dom_baseline.common import (
        BaselineConfig,
        model_dir,
        parse_models,
        report_dir,
    )
    from c2_analyzer.classifiers.dom_baseline.data import prepare_dataset
    from c2_analyzer.classifiers.dom_baseline.evaluate import confusion_text
    from c2_analyzer.classifiers.dom_baseline.report import run_report
    from c2_analyzer.classifiers.dom_baseline.train import train_all  # imports xgboost
    from c2_analyzer.dataset.manifest import manifests_dir

    config = BaselineConfig.load(BEHAVIOR_SOURCE)
    dataset = prepare_dataset(
        args.version,
        config.correlation_threshold,
        manifests=manifests_dir(store),
        source=BEHAVIOR_SOURCE,
    )
    print(
        f"Behavior features {dataset.feature_set_version}: {len(dataset.all_features)} -> "
        f"{len(dataset.features)} used (dropped on TRAIN: {len(dataset.dropped)} constant / "
        f"correlated); classes {dataset.labels}" + (" (PILOT)" if dataset.pilot else "")
    )
    started = time.perf_counter()
    bundles = train_all(dataset, config, parse_models(args.models), show_progress=not args.quiet)
    for bundle in bundles.values():
        mean, std = bundle["cv"]["mean"], bundle["cv"]["std"]
        params = ", ".join(f"{k}={v}" for k, v in bundle["params"].items())
        print(
            f"  {bundle['display_name']:<20} CV macro-F1 {mean['macro_f1']:.3f} +/- "
            f"{std['macro_f1']:.3f}  ({len(bundle['grid'])} points, {bundle['training_seconds']} s)"
            f"  {params}"
        )
    results = run_report(dataset, bundles, config)
    models, best = results["models"], results["best_model"]
    print(f"\nTrained + evaluated in {time.perf_counter() - started:.1f} s")
    print(f"Confusion matrix - {models[best]['display_name']} (test, rows = true):")
    print(confusion_text(models[best]["test"]["confusion_matrix"], results["classes"]))
    comparison = compare(args.version, results)
    folder = report_dir(config, args.version)
    paths = write_comparison(comparison, folder)
    print("\n" + comparison_markdown(comparison))
    print(
        f"Report: {folder / 'results.md'}\nComparison: {paths[1]}\n"
        f"Model card: {model_dir(config, args.version) / 'model_card.json'}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    # Evidence can contain any script; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    if args.command == "describe":
        print(describe_dictionary(markdown=args.markdown))
        return 0
    store = MetadataStore(args.metadata, args.raw_dir)
    commands = {"run": cmd_run, "one": cmd_one, "train-baseline": cmd_train_baseline}
    try:
        return commands[args.command](args, store)
    except (ValueError, KeyError, FileNotFoundError, FileSaveError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
