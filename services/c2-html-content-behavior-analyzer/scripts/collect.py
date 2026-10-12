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
from c2_analyzer.dataset.collection import (
    collect,
    progress_table,
    reason_breakdown,
    reason_code,
)
from c2_analyzer.dataset.feeds import (
    FEED_URLS,
    FEEDS,
    download_feed,
    import_feed,
    prune_candidates,
)
from c2_analyzer.dataset.fetcher import make_fetcher
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.repair import repair

EXAMPLES = """examples:
  python scripts/collect.py download --feed openphish
  python scripts/collect.py import --feed openphish --file data/feeds/openphish.txt
  python scripts/collect.py import --feed tranco --file data/feeds/tranco_top1m.csv.zip \\
      --top 1000 --sample 60
  python scripts/collect.py import --feed manual --file data/feeds/manual_urls.csv
  python scripts/collect.py fetch --label phishing --limit 60
  python scripts/collect.py retry-failed
  python scripts/collect.py progress
  python scripts/collect.py failures --label malware_delivery
  python scripts/collect.py repair --dry-run
  python scripts/collect.py prune --label malware_delivery
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

    failures = commands.add_parser("failures", help="list failed/skipped candidates and why")
    failures.add_argument("--label", choices=get_labels())
    failures.add_argument("--status", choices=("failed", "skipped"), help="only this status")
    failures.add_argument("--limit", type=int, help="list at most N candidates")

    prune = commands.add_parser(
        "prune", help="re-apply the import filters to pending candidates (marks them skipped)"
    )
    prune.add_argument("--label", choices=get_labels())

    fix = commands.add_parser("repair", help="fix candidates/metadata left inconsistent by a crash")
    fix.add_argument("--dry-run", action="store_true", help="only report, change nothing")
    return parser


def print_reasons(reasons, title: str) -> None:
    """Print reason codes, most common first (e.g. "non_html_content: 31")."""
    if reasons:
        print(title)
        for code, count in reasons.most_common():
            print(f"  {code}: {count}")


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
        summary = collect(to_fetch, fetcher, metadata, candidates)
    counts = ", ".join(f"{outcome}: {count}" for outcome, count in summary.counts.items())
    print(f"Done - {counts}")
    print_reasons(summary.reasons, "Skip/fail reasons:")
    if summary.reasons:
        print("Details: python scripts/collect.py failures")
    return 0


def cmd_progress(candidates: CandidateStore, metadata: MetadataStore) -> int:
    with pd.option_context("display.width", 200, "display.max_columns", 20):
        print("Registered samples (rows: label, columns: language)")
        print(progress_table(metadata.df).to_string())
        print("\nCandidates by status")
        print(candidates.status_counts().to_string())
    return 0


def cmd_failures(args: argparse.Namespace, candidates: CandidateStore) -> int:
    df = candidates.df
    rows = df[df["status"].isin([args.status] if args.status else ["failed", "skipped"])]
    if args.label:
        rows = rows[rows["suggested_label"] == args.label]
    if rows.empty:
        print("No failed or skipped candidates.")
        return 0

    print_reasons(reason_breakdown(rows), f"{len(rows)} candidate(s) by reason:")
    shown = rows if args.limit is None else rows.head(args.limit)
    table = pd.DataFrame(
        {
            "status": shown["status"],
            "label": shown["suggested_label"],
            "reason": shown["last_error"].map(reason_code),
            "tries": shown["attempts"],
            "url": shown["url"].str.slice(0, 70),
            "error": shown["last_error"].str.slice(0, 90),
        }
    )
    with pd.option_context("display.width", 250, "display.max_colwidth", 100):
        print()
        print(table.to_string(index=False))
    if len(shown) < len(rows):
        print(f"... {len(rows) - len(shown)} more (remove --limit to see all)")
    return 0


def cmd_prune(args: argparse.Namespace, candidates: CandidateStore) -> int:
    pruned = prune_candidates(candidates, label=args.label)
    candidates.save()
    print_reasons(pruned, f"Pruned {sum(pruned.values())} pending candidate(s) (now skipped):")
    pending = candidates.df[candidates.df["status"] == "pending"]
    if args.label:
        pending = pending[pending["suggested_label"] == args.label]
    print(
        f"{len(pending)} pending candidate(s) remain" + (f" for {args.label}" if args.label else "")
    )
    return 0


def cmd_repair(
    args: argparse.Namespace, candidates: CandidateStore, metadata: MetadataStore
) -> int:
    report = repair(candidates, metadata, dry_run=args.dry_run)
    if report.is_clean:
        print("Everything is consistent - nothing to repair.")
        return 0

    def did(action: str) -> str:  # "Would reset" in a dry run, "Reset" otherwise
        return f"Would {action}" if args.dry_run else action.capitalize()

    print(
        f"{did('reset')} {len(report.reset_to_pending)} candidate(s) to pending "
        "(marked fetched, but the sample is not in metadata.csv)"
    )
    for url in report.reset_to_pending:
        print(f"  {url}")
    print(f"{did('link')} {len(report.relinked)} candidate(s) to their already-saved sample")
    for url, sample_id in report.relinked:
        print(f"  {url} -> {sample_id}")
    print(f"{did('remove')} {len(report.temp_files)} leftover temp file(s)")
    for path in report.locked_temp_files:
        print(f"  could not remove (locked): {path}")

    if report.orphan_raw_files:
        print()
        print(f"{len(report.orphan_raw_files)} file(s) in data/raw have no metadata row:")
        for relative in report.orphan_raw_files:
            print(f"  {relative}")
        print("  They were NOT deleted. Register one with:")
        print(
            "    python scripts/build_metadata.py register --file data/raw/<label>/<file> "
            "--label <label> --language <lang> --source <source> --source-url <url>"
        )
        print("  or delete it if you cannot tell where it came from.")
    if report.missing_raw_files:
        print()
        print(
            f"{len(report.missing_raw_files)} metadata row(s) point to a missing file "
            "(often quarantined by antivirus): " + ", ".join(report.missing_raw_files)
        )
        print("  Restore them from quarantine. Details: python scripts/build_metadata.py validate")
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
        if args.command == "failures":
            return cmd_failures(args, candidates)
        if args.command == "prune":
            return cmd_prune(args, candidates)
        if args.command == "repair":
            return cmd_repair(args, candidates, metadata)
        return cmd_progress(candidates, metadata)
    except (ValueError, FileNotFoundError, RuntimeError, httpx.HTTPError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
