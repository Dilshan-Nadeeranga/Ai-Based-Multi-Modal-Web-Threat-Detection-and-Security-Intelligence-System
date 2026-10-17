"""Page text + language ID (Part 5 Batch A) and the scam-text corpus (Part 5 Batch B).

Part 5: Multilingual scam content analyzer.

Why: a thin command-line wrapper; all logic is in c2_analyzer.content.
- ``extract``  text segments + languages + page_text for every sample of a frozen
               dataset version (Part 2 is run and saved for missing samples), the
               text_index.csv, the summary report and the language-mismatch
               review list (metadata.csv is never changed).
- ``one``      one page: segments grouped by field with language tags, then page_text.
- ``build``    the intent corpus corpus_v1 (page segments + real messages + synthetic
               templates + machine translations; see content/corpus_builder.py),
               then the stats report. Review decisions are re-applied.
- ``stats``    reports/content/corpus_v1_stats.{json,md} + the key tables.
- ``export-mt-input``  English TRAIN rows for the NLLB Colab notebook (05_corpus_mt_colab).
- ``freeze``   data/corpus/manifests/<name>.{csv,json} (ids + hashes, no text; never
               overwritten).
Research integrity: synthetic / machine-translated rows are TRAIN ONLY; val / test
contain only real text. Part 5 prepares text for Part 6; it does not classify pages.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.config import get_labels
from c2_analyzer.content.batch import export_json, output_dir, run_version
from c2_analyzer.content.corpus import CorpusPaths, freeze_corpus
from c2_analyzer.content.corpus_builder import build_corpus, export_mt_input
from c2_analyzer.content.corpus_stats import compute_stats, write_stats
from c2_analyzer.content.extractor import extract_content
from c2_analyzer.content.report import describe_result, summarize, write_report
from c2_analyzer.dataset.manifest import manifests_dir
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.splits import SplitError
from c2_analyzer.preprocessing.loader import from_file, from_sample
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.utils.hashing import sha256_file
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/build_text_corpus.py extract --version v0.3
  python scripts/build_text_corpus.py extract --version v0.3 --force --workers 4
  python scripts/build_text_corpus.py one --sample-id c2_benign_000123
  python scripts/build_text_corpus.py one --file page.html --url https://example.com/ [--json]
  python scripts/build_text_corpus.py build --version v0.3
  python scripts/build_text_corpus.py stats
  python scripts/build_text_corpus.py export-mt-input
  python scripts/build_text_corpus.py freeze --name corpus_v1 --notes "first verified corpus"
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

    build = commands.add_parser("build", help="build the intent corpus corpus_v1 + stats")
    build.add_argument("--version", required=True, help="dataset version (text + shared split)")
    build.add_argument("--text-dir", type=Path, help="default data/processed/text/<version>")
    commands.add_parser("stats", help="corpus statistics + integrity checks")
    mt = commands.add_parser("export-mt-input", help="English train rows for the MT notebook")
    mt.add_argument(
        "--source-type", action="append",
        choices=["page_segment", "real_message", "synthetic_template"],
        help="only these sources (repeatable; default all except machine_translation)",
    )  # fmt: skip
    freeze = commands.add_parser("freeze", help="freeze the corpus into a manifest")
    freeze.add_argument("--name", required=True, help="e.g. corpus_v1")
    freeze.add_argument("--notes", help="free text stored in the manifest")
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


def print_stats(stats: dict) -> None:
    """The tables shown after every build: language x intent per source, synthetic
    share per split and the real Sinhala / Tamil gap."""
    intents = stats["intents"]
    short = [name[:11] for name in intents]
    widths = [4, 9] + [12] * len(intents) + [7]
    for source, block in stats["by_source"].items():
        if not block["rows"]:
            continue
        print(f"\n{source} ({block['rows']} rows; split {block['split']}) - language x intent:")
        print(_row(["", "language"] + short + ["total"], widths))
        for language, row in block["language_x_intent"].items():
            if sum(row.values()):
                print(_row(["", language] + list(row.values()) + [sum(row.values())], widths))

    print("\nSynthetic share per split (val / test must be 0 %):")
    for split, row in stats["synthetic_share_per_split"].items():
        print(
            f"  {split:<6} {row['rows']:>6} rows  {row['synthetic']:>5} synthetic  "
            f"{row['share_percent']:>6} %"
        )

    print("\nReal Sinhala / Tamil text in val + test per intent (count / target):")
    for language, block in stats["real_text_gap"].items():
        cells = [
            f"{name}={row['count']}/{row['target']}" for name, row in block["per_intent"].items()
        ]
        print(f"  {language}: " + "  ".join(cells))
        print(
            f"      {block['intents_meeting_target']} of {block['scam_intents']} scam intents "
            f"meet the target; total gap {block['total_gap']} rows"
        )

    check = stats["integrity"]
    verification = stats["verification"]
    print(
        f"\nIntegrity: {'PASSED' if check['passed'] else 'FAILED'} (synthetic in val/test "
        f"{check['synthetic_rows_in_val_test']}, texts in several splits "
        f"{check['texts_in_several_splits']}, groups in several splits "
        f"{check['groups_in_several_splits']})"
    )
    print(
        f"Rows {stats['rows']} (active {stats['active_rows']}); verified "
        f"{verification['verified_percent']} %; needs review {verification['needs_review']}"
    )


def cmd_build(args: argparse.Namespace, store: MetadataStore) -> int:
    paths = CorpusPaths.from_config()
    # the shared split must still match the frozen dataset manifest (as in Part 4)
    _, info = build_corpus(
        args.version, paths, text_dir=args.text_dir, manifests=manifests_dir(store)
    )
    print(f"Built {paths.corpus_csv} ({info['rows']} rows) from dataset {args.version}")
    for source, counts in info["sources"].items():
        print(f"  {source}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    print(
        f"  cross-split duplicates resolved: {info['leakage_resolved']}; reviews applied: "
        f"{info['reviews_applied']} (orphaned {len(info['reviews_orphaned'])})"
    )
    for warning in info["warnings"]:
        print(f"  WARNING: {warning}")
    return cmd_stats(args, store)


def cmd_stats(args: argparse.Namespace, store: MetadataStore) -> int:
    paths = CorpusPaths.from_config()
    stats = compute_stats(paths)
    print_stats(stats)
    json_path, md_path = write_stats(stats, paths)
    print(f"\nReport:  {json_path}\n         {md_path}")
    return 0 if stats["integrity"]["passed"] else 1


def cmd_export_mt(args: argparse.Namespace, store: MetadataStore) -> int:
    path, count = export_mt_input(CorpusPaths.from_config(), args.source_type)
    print(f"Wrote {count} English train row(s) to {path}")
    print("Upload it to notebooks/05_corpus_mt_colab.ipynb, put the returned mt_si.csv /")
    print("mt_ta.csv into the same folder, then run build again.")
    return 0


def cmd_freeze(args: argparse.Namespace, store: MetadataStore) -> int:
    path, info = freeze_corpus(CorpusPaths.from_config(), args.name, args.notes)
    print(
        f"Froze {info['rows']} rows ({info['active_rows']} active, {info['verified_rows']} "
        f"verified) -> {path}"
    )
    print(f"fingerprint {info['fingerprint'][:16]}...  dataset {info['dataset_version']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Page text can be in any script; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    store = MetadataStore(args.metadata, args.raw_dir)
    commands = {
        "extract": cmd_extract,
        "one": cmd_one,
        "build": cmd_build,
        "stats": cmd_stats,
        "export-mt-input": cmd_export_mt,
        "freeze": cmd_freeze,
    }
    try:
        return commands[args.command](args, store)
    except (
        ValueError,
        KeyError,
        FileNotFoundError,
        FileExistsError,
        FileSaveError,
        SplitError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
