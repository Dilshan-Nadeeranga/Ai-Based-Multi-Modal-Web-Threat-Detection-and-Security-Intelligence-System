"""Extract DOM security features (Part 3): a dataset version, one page, or the dictionary.

Part 3: DOM structural analysis.

Why: a thin command-line wrapper. ``run`` extracts the features of every
sample of a frozen dataset version (from the stored Part 2 JSON; Part 2 is run
and saved for any missing sample) and writes dom_features.csv - the Part 4
input - plus the descriptive report. ``one`` shows the features and evidence
of a single page. ``describe`` prints the feature dictionary for the report.
All logic is in c2_analyzer.dom. Nothing here runs JavaScript or downloads anything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.config import get_labels
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dom.batch import run_version
from c2_analyzer.dom.exporter import export_json, output_dir
from c2_analyzer.dom.pipeline import extract_dom_features
from c2_analyzer.dom.report import (
    describe_dictionary,
    describe_result,
    dictionary_markdown,
    summarize,
    warning_lines,
    write_report,
)
from c2_analyzer.preprocessing.loader import from_file, from_sample
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.utils.hashing import sha256_file
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/extract_dom_features.py run --version v0.1
  python scripts/extract_dom_features.py run --version v0.1 --force --workers 4
  python scripts/extract_dom_features.py one --sample-id c2_phishing_000081
  python scripts/extract_dom_features.py one --file page.html --url https://example.com/login
  python scripts/extract_dom_features.py describe [--markdown]
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    parser.add_argument(
        "--out-dir", type=Path, help="default data/processed/dom_features/<version>"
    )
    parser.add_argument("--reports-dir", type=Path, help="default reports/dom_features")
    parser.add_argument(
        "--parsed-dir",
        type=Path,
        help="Part 2 JSON folder (default data/processed/parsed_html/<v>)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="features for every sample of a frozen dataset version")
    run.add_argument("--version", required=True, help="e.g. v0.1 (see data/metadata/manifests/)")
    run.add_argument("--label", choices=get_labels(), help="only this label (CSV keeps all)")
    run.add_argument("--limit", type=int, help="process at most N samples")
    run.add_argument("--workers", type=int, help="parallel processes (default from config: 4)")
    run.add_argument("--force", action="store_true", help="redo samples that are already done")

    one = commands.add_parser("one", help="features + evidence of one page (text only)")
    source = one.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample-id", help="a registered sample")
    source.add_argument("--file", type=Path, help="any local .html file")
    one.add_argument("--url", help="the page's address (for --file; never fetched)")
    one.add_argument("--version", help="dataset version to record in the output")
    one.add_argument("--save", action="store_true", help="also save the JSON (adhoc folder)")

    describe = commands.add_parser("describe", help="print the feature dictionary")
    describe.add_argument("--markdown", action="store_true", help="as a Markdown table")
    return parser


def _fmt(value: float) -> str:
    return f"{value:,.3g}" if abs(value) < 1000 else f"{value:,.0f}"


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
    )
    filters = {"label": args.label, "limit": args.limit, "force": args.force}
    summary = summarize(rows, results, args.version, seconds, filters)
    paths = write_report(summary, rows, args.reports_dir)

    counts, timing, warn = summary["counts"], summary["timing"], summary["warnings"]
    print(
        f"Dataset {args.version}: {counts['run_total']} page(s) - processed {counts['processed']}, "
        f"unchanged {counts['skipped_unchanged']}, failed {counts['failed']} "
        f"(Part 2 run for {counts['part2_processed_now']}); rows in CSV: {counts['rows_in_csv']}"
    )
    print(
        f"Feature set {summary['feature_set_version']}: {summary['feature_count']} features; "
        f"pages with a failed feature group: {counts['pages_with_group_errors']}"
    )
    print(
        f"Time per page: avg {timing['avg_ms']} ms, p95 {timing['p95_ms']} ms, "
        f"max {timing['max_ms']} ms ({timing['pages_timed']} timed); "
        f"wall {timing['wall_seconds']} s"
    )
    for failure in summary["failures"][:20]:
        print(f"  FAILED {failure['sample_id']}: {failure['error']}")

    labels = summary["labels"]
    print("\nMost separating features (descriptive: mutual information, label medians):")
    print(f"{'feature':<36}{'MI':>7}{'spread':>8}" + "".join(f"{x[:16]:>17}" for x in labels))
    for row in summary["separation"][: len(summary["top_separating"])]:
        print(
            f"{row['feature']:<36}{row['mutual_information']:>7.3f}{row['median_spread']:>8.2f}"
            + "".join(f"{_fmt(row['medians'][label]):>17}" for label in labels)
        )
    print("\nWarnings:")
    for line in warning_lines(warn):
        print(f"  {line}")
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
    result = extract_dom_features(preprocess(raw), raw.html)
    print(describe_result(result, label=raw.label))
    if args.save:
        path = export_json(result, (args.out_dir or output_dir(args.version)) / f"{name}.json")
        print(f"\nSaved {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Evidence can contain Sinhala/Tamil; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    if args.command == "describe":
        print(dictionary_markdown() if args.markdown else describe_dictionary())
        return 0
    store = MetadataStore(args.metadata, args.raw_dir)
    try:
        if args.command == "run":
            return cmd_run(args, store)
        return cmd_one(args, store)
    except (ValueError, KeyError, FileNotFoundError, FileSaveError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
