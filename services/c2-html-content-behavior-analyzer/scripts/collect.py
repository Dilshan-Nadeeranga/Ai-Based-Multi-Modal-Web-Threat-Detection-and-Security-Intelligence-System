"""Collect dataset samples: import candidate URLs, fetch them safely, track progress.

Part 1: Multilingual dataset preparation (Batch B).

Why: one command-line tool for the whole collection workflow, so collecting
hundreds of pages is repeatable and safe. It is a thin wrapper; the logic is
in c2_analyzer.dataset (feeds, candidates, fetcher, collection).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx
import pandas as pd

from c2_analyzer.config import get_labels, load_yaml_config, resolve_path
from c2_analyzer.dataset.candidates import CandidateStore
from c2_analyzer.dataset.collection import collect, progress_table
from c2_analyzer.dataset.feeds import FEED_URLS, FEEDS, download_feed, import_feed
from c2_analyzer.dataset.fetcher import make_fetcher
from c2_analyzer.dataset.metadata import MetadataStore

EXAMPLES = """examples:
  python scripts/collect.py download --feed openphish
  python scripts/collect.py import --feed openphish --file data/feeds/openphish.txt
  python scripts/collect.py import --feed tranco --file data/feeds/tranco_top1m.csv.zip \
      --top 1000 --sample 60
  python scripts/collect.py import --feed manual --file data/feeds/manual_urls.csv
  python scripts/collect.py fetch --label phishing --limit 60
  python scripts/collect.py retry-failed
  python scripts/collect.py progress
"""


def build_parser() -> argparse.ArgumentParser:
    collection = load_yaml_config("config")["collection"]
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--candidates", type=Path, help="candidates CSV (default from config)")
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    commands = parser.add_subparsers(dest="command", required=True)

    download = commands.add_parser("download", help="download a public feed file (network)")
    download.add_argument("--feed", required=True, choices=sorted(FEED_URLS))
    download.add_argument("--out-dir", type=Path, default=Path(collection["feeds_dir"]))

    imp = commands.add_parser("import", help="add candidate URLs from a local feed file")
    imp.add_argument("--feed", required=True, choices=FEEDS)
    imp.add_argument("--file", type=Path, required=True)
    imp.add_argument("--top", type=int, help="tranco: use the top N domains (default from config)")
    imp.add_argument("--sample", type=int, help="tranco: random sample of N from the top N")

    for name, help_text in (
        ("fetch", "fetch pending candidates and register the pages"),
        ("retry-failed", "fetch failed candidates again"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--label", choices=get_labels())
        command.add_argument("--limit", type=int, help="process at most N candidates")
        command.add_argument("--mode", choices=("static", "rendered"), default="static")
        command.add_argument("--rate", type=float, help="max requests per second (default 1.0)")
        if name == "retry-failed":
            command.add_argument(
                "--max-attempts", type=int, default=collection["max_attempts"],
                help="only retry candidates tried fewer times than this",
            )  # fmt: skip

    commands.add_parser("progress", help="show collected samples vs targets")
    return parser


def cmd_download(args: argparse.Namespace) -> int:
    path = download_feed(args.feed, resolve_path(args.out_dir))
    print(f"Saved {args.feed} feed to {path}")
    return 0


def cmd_import(args: argparse.Namespace, candidates: CandidateStore) -> int:
    result = import_feed(args.feed, args.file, top=args.top, sample=args.sample)
    added, already = candidates.add_many(result.candidates)
    candidates.save()
    print(f"Imported {added} new candidate(s) from {args.feed}; {already} already queued.")
    for reason, count in result.filtered.items():
        print(f"  filtered out: {count} ({reason})")
    if result.rejected:
        print(f"  rejected {len(result.rejected)} invalid line(s):")
        for line in result.rejected[:10]:
            print(f"    {line}")
        if len(result.rejected) > 10:
            print(f"    ... and {len(result.rejected) - 10} more")
    return 0


def cmd_fetch(args: argparse.Namespace, candidates: CandidateStore, metadata: MetadataStore) -> int:
    if args.command == "retry-failed":
        to_fetch = candidates.retryable(args.max_attempts, label=args.label, limit=args.limit)
    else:
        to_fetch = candidates.next_pending(label=args.label, limit=args.limit)
    if not to_fetch:
        print("Nothing to fetch.")
        return 0

    print(f"Fetching {len(to_fetch)} candidate(s) in {args.mode} mode...")
    with make_fetcher(args.mode, rate=args.rate) as fetcher:
        counts = collect(to_fetch, fetcher, metadata, candidates)
    summary = ", ".join(f"{outcome}: {count}" for outcome, count in counts.items())
    print(f"Done - {summary}")
    return 0


def cmd_progress(candidates: CandidateStore, metadata: MetadataStore) -> int:
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print("Registered samples (rows: label, columns: language)")
        print(progress_table(metadata.df).to_string())
        print("\nCandidates by status")
        print(candidates.status_counts().to_string())
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    candidates = CandidateStore(args.candidates)
    metadata = MetadataStore(args.metadata, args.raw_dir)
    try:
        if args.command == "download":
            return cmd_download(args)
        if args.command == "import":
            return cmd_import(args, candidates)
        if args.command in ("fetch", "retry-failed"):
            return cmd_fetch(args, candidates, metadata)
        return cmd_progress(candidates, metadata)
    except (ValueError, FileNotFoundError, RuntimeError, httpx.HTTPError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
