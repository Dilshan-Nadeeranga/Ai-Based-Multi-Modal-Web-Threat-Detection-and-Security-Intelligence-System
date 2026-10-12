"""Preprocess HTML into ParsedPage JSON (a whole dataset version, or one page).

Part 2: HTML preprocessing pipeline.

Why: a thin command-line wrapper. ``run`` processes every sample of a
frozen dataset version (Part 1 manifest) in parallel and writes the
outputs + a summary report; ``one`` shows what the pipeline extracts from a
single page, as text. The logic is in c2_analyzer.preprocessing.

Nothing here runs JavaScript or downloads anything. On Windows the worker
processes are started with "spawn", which is why everything below runs
only under ``if __name__ == "__main__"``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.config import get_labels
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.preprocessing.batch import output_dir, run_version, save_page
from c2_analyzer.preprocessing.loader import from_file, from_sample
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.preprocessing.report import describe_page, summarize, write_summary
from c2_analyzer.utils.hashing import sha256_file
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/preprocess_html.py run --version v0.1
  python scripts/preprocess_html.py run --version v0.1 --label phishing --limit 20 --workers 2
  python scripts/preprocess_html.py run --version v0.1 --force
  python scripts/preprocess_html.py one --sample-id c2_phishing_000012
  python scripts/preprocess_html.py one --file page.html --url https://example.com/login
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    parser.add_argument("--out-dir", type=Path, help="default data/processed/parsed_html/<version>")
    parser.add_argument("--reports-dir", type=Path, help="default reports/preprocessing")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="preprocess every sample of a frozen dataset version")
    run.add_argument("--version", required=True, help="e.g. v0.1 (see data/metadata/manifests/)")
    run.add_argument("--label", choices=get_labels())
    run.add_argument("--limit", type=int, help="process at most N samples")
    run.add_argument("--workers", type=int, help="parallel processes (default from config: 4)")
    run.add_argument("--force", action="store_true", help="redo samples that are already done")

    one = commands.add_parser("one", help="show what is extracted from one page (text only)")
    source = one.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample-id", help="a registered sample")
    source.add_argument("--file", type=Path, help="any local .html file")
    one.add_argument("--url", help="the page's address (for --file; resolves relative links)")
    one.add_argument("--version", help="dataset version to record in the output")
    one.add_argument("--save", action="store_true", help="also save JSON + TXT (adhoc folder)")
    return parser


def cmd_run(args: argparse.Namespace, store: MetadataStore) -> int:
    results, seconds = run_version(
        store,
        args.version,
        label=args.label,
        limit=args.limit,
        workers=args.workers,
        force=args.force,
        out_dir=args.out_dir,
    )
    filters = {"label": args.label, "limit": args.limit, "force": args.force}
    summary = summarize(results, args.version, seconds, filters)
    json_path, md_path = write_summary(summary, args.reports_dir)

    counts, timing = summary["counts"], summary["timing"]
    print(
        f"Dataset {args.version}: {counts['total']} page(s) - processed {counts['processed']}, "
        f"unchanged {counts['skipped_unchanged']}, failed {counts['failed']}"
    )
    print(
        f"Step errors (partial results): {len(summary['pages_with_step_errors'])}, "
        f"parser fallbacks: {len(summary['parser_fallbacks'])}, "
        f"truncated: {len(summary['truncated'])}"
    )
    print(
        f"Time per page: avg {timing['avg_processing_ms']} ms, "
        f"p95 {timing['p95_processing_ms']} ms, max {timing['max_processing_ms']} ms; "
        f"wall time {timing['wall_seconds']} s"
    )
    for failure in summary["failures"][:20]:
        print(f"  FAILED {failure['sample_id']}: {failure['error']}")
    print()
    print(
        f"{'label':<18}{'pages':>6}{'med.chars':>10}{'%forms':>8}{'%passw':>8}"
        f"{'%inlJS':>8}{'%extJS':>8}{'%iframe':>8}{'%refr':>7}"
    )
    for label, row in summary["per_label"].items():
        print(
            f"{label:<18}{row['pages']:>6}{row['median_visible_chars']:>10,.0f}"
            f"{row['pct_with_forms']:>8}{row['pct_with_password_input']:>8}"
            f"{row['pct_with_inline_scripts']:>8}{row['pct_with_external_scripts']:>8}"
            f"{row['pct_with_iframes']:>8}{row['pct_with_meta_refresh']:>7}"
        )
    print()
    print(f"Outputs: {args.out_dir or output_dir(args.version)}")
    print(f"Summary: {json_path}\n         {md_path}")
    return 1 if counts["failed"] else 0


def cmd_one(args: argparse.Namespace, store: MetadataStore) -> int:
    if args.sample_id:
        raw = from_sample(store, args.sample_id, dataset_version=args.version)
        name = args.sample_id
    else:
        raw = from_file(args.file, page_url=args.url)
        name = sha256_file(args.file)[:16]  # ad-hoc pages have no sample id
    page = preprocess(raw)
    print(describe_page(page, label=raw.label))
    if args.save:
        path = save_page(page, args.out_dir or output_dir(args.version), name)
        print(f"\nSaved {path} (+ .txt)")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Page text can be Sinhala/Tamil; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
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
