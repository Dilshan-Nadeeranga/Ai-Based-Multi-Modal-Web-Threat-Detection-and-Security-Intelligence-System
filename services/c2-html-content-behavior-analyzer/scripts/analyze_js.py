"""Static JavaScript analysis (Part 7): a dataset version, one page, or the feature list.

Part 7: Static JavaScript intent analyzer.

Why: a thin command-line wrapper. ``run`` analyses the JavaScript of every
sample of a frozen dataset version (from the stored Part 2 JSON; Part 2 is run
and saved for any missing sample), writes js_features.csv and the descriptive
report. ``one`` shows the detections of a single page grouped by category,
with line numbers and snippets. ``describe`` prints the feature dictionary.
All logic is in c2_analyzer.js_analyzer. Nothing here runs JavaScript or
downloads anything (external scripts are analysed by address only).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.config import get_labels
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.js_analyzer.batch import export_json, output_dir, run_version
from c2_analyzer.js_analyzer.pipeline import analyze_js
from c2_analyzer.js_analyzer.report import (
    describe_dictionary,
    describe_result,
    summarize,
    write_report,
)
from c2_analyzer.preprocessing.loader import from_file, from_sample
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.utils.hashing import sha256_file
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/analyze_js.py run --version v0.2
  python scripts/analyze_js.py run --version v0.2 --force --workers 4
  python scripts/analyze_js.py one --sample-id c2_phishing_000081
  python scripts/analyze_js.py one --file page.html --url https://example.com/login [--json]
  python scripts/analyze_js.py describe [--markdown]
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    parser.add_argument("--out-dir", type=Path, help="default data/processed/js/<version>")
    parser.add_argument("--reports-dir", type=Path, help="default reports/js_analysis")
    parser.add_argument(
        "--parsed-dir",
        type=Path,
        help="Part 2 JSON folder (default data/processed/parsed_html/<v>)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="analyse every sample of a frozen dataset version")
    run.add_argument("--version", required=True, help="e.g. v0.2 (see data/metadata/manifests/)")
    run.add_argument("--label", choices=get_labels(), help="only this label (CSV keeps all)")
    run.add_argument("--limit", type=int, help="process at most N samples")
    run.add_argument("--workers", type=int, help="parallel processes (default from config: 4)")
    run.add_argument("--force", action="store_true", help="redo samples that are already done")

    one = commands.add_parser("one", help="detections of one page, grouped (text only)")
    source = one.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample-id", help="a registered sample")
    source.add_argument("--file", type=Path, help="any local .html file")
    one.add_argument("--url", help="the page's address (for --file; never fetched)")
    one.add_argument("--version", help="dataset version to record in the output")
    one.add_argument("--json", action="store_true", help="print the full JsAnalysisResult JSON")
    one.add_argument("--save", action="store_true", help="also save the JSON (adhoc folder)")

    describe = commands.add_parser("describe", help="print the JS feature dictionary")
    describe.add_argument("--markdown", action="store_true", help="as a Markdown table")
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
    )
    filters = {"label": args.label, "limit": args.limit, "force": args.force}
    summary = summarize(rows, results, args.version, seconds, filters)
    paths = write_report(summary, args.reports_dir)

    counts, timing, parsing, library = (
        summary["counts"],
        summary["timing"],
        summary["parsing"],
        summary["library"],
    )
    print(
        f"Dataset {args.version}: {counts['run_total']} page(s) - processed {counts['processed']}, "
        f"unchanged {counts['skipped_unchanged']}, failed {counts['failed']} "
        f"(Part 2 run for {counts['part2_processed_now']}); rows in CSV: {counts['rows_in_csv']}"
    )
    print(
        f"Parser: {summary['parser']}; feature set {summary['feature_set_version']} "
        f"({summary['feature_count']} features)"
    )
    print(
        f"Scripts analysed: {parsing['scripts_analyzed']} - parse success rate "
        f"{parsing['parse_success_rate']} % (lexical fallback {parsing['lexical_fallback']}, "
        f"timed out {parsing['timed_out']}, truncated {parsing['truncated']})"
    )
    print(
        f"Library code: {library['library_scripts']} of {library['inline_scripts']} inline scripts "
        f"({library['library_script_share']} %, {library['library_char_share']} % of characters); "
        f"detections in libraries {library['detections_in_library']}, "
        f"page-own {library['detections_page_own']}"
    )
    print(
        f"Time per page: avg {timing['avg_ms']} ms, median {timing['median_ms']} ms, "
        f"p95 {timing['p95_ms']} ms, max {timing['max_ms']} ms ({timing['pages_timed']} timed); "
        f"wall {timing['wall_seconds']} s"
    )
    for failure in summary["failures"][:20]:
        print(f"  FAILED {failure['sample_id']}: {failure['error']}")

    labels = summary["labels"]
    print("\n% of pages using each API category (page-own code):")
    width = max(len(c) for c in summary["categories"]) + 2
    print(f"{'category':<{width}}" + "".join(f"{label[:16]:>18}" for label in labels))
    print(
        f"{'(pages)':<{width}}"
        + "".join(f"{summary['per_label'][label]['pages']:>18}" for label in labels)
    )
    for category in summary["categories"]:
        print(
            f"{category:<{width}}"
            + "".join(
                f"{summary['per_label'][label]['category_pct'][category]:>17.1f}%"
                for label in labels
            )
        )
    print(
        "\nMost used APIs (page-own): "
        + ", ".join(
            f"{a['api']} {a['page_own']} ({a['pages']} pages)" for a in summary["top_apis"][:10]
        )
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
    result = analyze_js(preprocess(raw))
    if args.json:
        print(result.model_dump_json(indent=1))
    else:
        print(describe_result(result, label=raw.label))
    if args.save:
        path = export_json(result, (args.out_dir or output_dir(args.version)) / f"{name}.json")
        print(f"\nSaved {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Snippets can contain any script; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    if args.command == "describe":
        print(describe_dictionary(markdown=args.markdown))
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
