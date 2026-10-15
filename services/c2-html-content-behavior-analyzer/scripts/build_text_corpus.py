"""Page text + language ID (Part 5, Batch A): a whole dataset version or one page.

Part 5: Multilingual scam content analyzer.

Why: a thin command-line wrapper; all logic is in c2_analyzer.content.
- ``extract``  text segments + languages + page_text for every sample of a frozen
               dataset version (Part 2 is run and saved for missing samples), the
               text_index.csv, the summary report and the language-mismatch
               review list (metadata.csv is never changed).
- ``one``      one page: segments grouped by field with language tags, then page_text.
Part 5 prepares text for Part 6; it does not classify pages.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.config import get_labels
from c2_analyzer.content.batch import export_json, output_dir, run_version
from c2_analyzer.content.extractor import extract_content
from c2_analyzer.content.report import describe_result, summarize, write_report
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.preprocessing.loader import from_file, from_sample
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.utils.hashing import sha256_file
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/build_text_corpus.py extract --version v0.3
  python scripts/build_text_corpus.py extract --version v0.3 --force --workers 4
  python scripts/build_text_corpus.py one --sample-id c2_benign_000123
  python scripts/build_text_corpus.py one --file page.html --url https://example.com/ [--json]
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    parser.add_argument("--out-dir", type=Path, help="default data/processed/text/<version>")
    parser.add_argument("--reports-dir", type=Path, help="default reports/content")
    parser.add_argument("--parsed-dir", type=Path, help="Part 2 JSON folder")
    commands = parser.add_subparsers(dest="command", required=True)

    extract = commands.add_parser("extract", help="text + language of a frozen dataset version")
    extract.add_argument("--version", required=True, help="e.g. v0.3 (data/metadata/manifests/)")
    extract.add_argument("--label", choices=get_labels(), help="only this label (index keeps all)")
    extract.add_argument("--limit", type=int, help="process at most N samples")
    extract.add_argument("--workers", type=int, help="parallel processes (default from config: 4)")
    extract.add_argument("--force", action="store_true", help="redo samples that are already done")

    one = commands.add_parser("one", help="segments + languages + page_text of one page")
    source = one.add_mutually_exclusive_group(required=True)
    source.add_argument("--sample-id", help="a registered sample")
    source.add_argument("--file", type=Path, help="any local .html file")
    one.add_argument("--url", help="the page's address (for --file; never fetched)")
    one.add_argument("--version", help="dataset version to record in the output")
    one.add_argument("--json", action="store_true", help="print the full PageText JSON")
    one.add_argument("--save", action="store_true", help="also save the JSON (adhoc folder)")
    return parser


def _row(cells: list, widths: list[int]) -> str:
    return "".join(f"{str(cell):>{width}}" for cell, width in zip(cells, widths, strict=True))


def cmd_extract(args: argparse.Namespace, store: MetadataStore) -> int:
    results, seconds, stored, index_path = run_version(
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
    summary = summarize(stored, results, args.version, seconds, filters)
    paths = write_report(summary, stored, args.reports_dir)
    counts = summary["counts"]
    print(
        f"Dataset {args.version}: {counts['run_total']} page(s) - processed {counts['processed']}, "
        f"unchanged {counts['skipped_unchanged']}, failed {counts['failed']} (Part 2 run for "
        f"{counts['part2_processed_now']}); rows in index: {counts['pages_in_index']}; empty text "
        f"{counts['empty_pages']}; language backend {summary['language_backend']}; wall "
        f"{summary['timing']['wall_seconds']} s, median {summary['timing']['median_ms']} ms/page"
    )
    for failure in summary["failures"][:20]:
        print(f"  FAILED {failure['sample_id']}: {failure['error']}")

    labels, langs = summary["labels"], summary["detected_languages"]
    widths = [18, 7] + [9] * len(langs)
    print("\nPage language per label (pages):")
    print(_row(["label", "pages"] + langs, widths))
    for label in labels:
        dist = summary["language_distribution"][label]
        print(_row([label, summary["pages_per_label"][label]] + [dist[x] for x in langs], widths))

    print("\nMetadata language (rows, Part 1 hint) vs detected (columns, Part 5):")
    widths = [18] + [9] * len(langs)
    print(_row(["metadata"] + langs, widths))
    for meta, row in summary["metadata_vs_detected"].items():
        print(_row([meta] + [row[x] for x in langs], widths))
    print(
        f"{counts['language_mismatches']} mismatch(es) listed for review in "
        f"{paths[2].name} (metadata.csv was NOT changed)"
    )
    print(f"\nIndex:   {index_path}")
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
    result = extract_content(page, raw.html)
    if args.json:
        print(result.model_dump_json(indent=1))
    else:
        print(describe_result(result, label=raw.label))
    if args.save:
        path = export_json(result, (args.out_dir or output_dir(args.version)) / f"{name}.json")
        print(f"\nSaved {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Page text can be in any script; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    store = MetadataStore(args.metadata, args.raw_dir)
    commands = {"extract": cmd_extract, "one": cmd_one}
    try:
        return commands[args.command](args, store)
    except (ValueError, KeyError, FileNotFoundError, FileSaveError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
