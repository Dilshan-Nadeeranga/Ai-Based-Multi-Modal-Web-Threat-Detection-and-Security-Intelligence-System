"""Clean the dataset: flag bad pages (quality) and cluster near-duplicates (dedup).

Part 1: Multilingual dataset preparation (Batch C, Task 11).

Why: a thin command-line wrapper so the cleaning steps can be repeated after
every collection run. The logic is in c2_analyzer.dataset.quality and
c2_analyzer.dataset.deduplicator. Nothing is ever deleted: these commands
only set metadata fields (quality_flag, cluster_id, is_duplicate_of) and
write reports to reports/dataset_stats/.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.dataset.deduplicator import run_dedup
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.quality import run_quality, usable_flags
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/deduplicate.py quality
  python scripts/deduplicate.py dedup --dry-run
  python scripts/deduplicate.py all
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    parser.add_argument("--reports-dir", type=Path, help="default reports/dataset_stats")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("quality", "flag empty / parked / error / challenge / suspended pages"),
        ("dedup", "cluster near-duplicate pages and mark duplicates"),
        ("all", "quality, then dedup"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--dry-run", action="store_true", help="show results, save nothing")
    return parser


def print_quality(result) -> None:
    print("Quality flags:")
    for flag, count in result.counts.most_common():
        note = "" if flag in usable_flags() else "   (proposed for exclusion)"
        print(f"  {flag}: {count}{note}")
    print(f"{len(result.changed)} flag(s) changed")
    if result.missing_files:
        print(f"{len(result.missing_files)} file(s) missing (see build_metadata.py validate)")


def print_dedup(result) -> None:
    summary = result.summary()
    print("Near-duplicate clustering:")
    print(f"  samples:                       {summary['samples']}")
    print(f"  compared:                      {summary['compared']}")
    for reason, count in summary["not_compared"].items():
        print(f"    not compared ({reason}): {count}")
    print(f"  clusters:                      {summary['clusters']}")
    print(f"  clusters with near-duplicates: {summary['clusters_with_near_duplicates']}")
    print(f"  duplicates marked:             {summary['duplicates_marked']}")
    print(f"  label conflicts:               {summary['label_conflicts']}")
    for cluster in result.multi_clusters[:10]:
        role = "CONFLICT " + "/".join(cluster.labels) if cluster.conflict else cluster.labels[0]
        members = ", ".join(cluster.members[:5])
        print(f"    {cluster.cluster_id}: {cluster.size} pages [{role}] {members}")
    if len(result.multi_clusters) > 10:
        print(f"    ... {len(result.multi_clusters) - 10} more in dedup_report.json")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = MetadataStore(args.metadata, args.raw_dir)
    try:
        if args.command in ("quality", "all"):
            print_quality(run_quality(store, dry_run=args.dry_run, show_progress=True))
        if args.command in ("dedup", "all"):
            result = run_dedup(
                store, dry_run=args.dry_run, reports_dir=args.reports_dir, show_progress=True
            )
            print_dedup(result)
    except (ValueError, FileNotFoundError, FileSaveError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print("Dry run - nothing was saved." if args.dry_run else "Saved.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
