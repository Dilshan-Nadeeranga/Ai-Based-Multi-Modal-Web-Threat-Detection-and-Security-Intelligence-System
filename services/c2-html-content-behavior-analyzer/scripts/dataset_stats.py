"""Dataset statistics, and frozen dataset versions for reproducible experiments.

Part 1: Multilingual dataset preparation (Batch D, Task 13).

Why: one command produces the numbers, tables and figures for the progress
report, and two commands freeze / check the exact dataset a model was
trained on. Thin wrapper: the logic is in c2_analyzer.dataset.statistics,
stats_report and manifest.

  stats    write reports/dataset_stats/dataset_stats.{json,md} + figures/
  freeze   save the clean view as data/metadata/manifests/dataset_<version>.csv/.json
  verify   check every file of a frozen version still exists with the same sha256
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.config import get_labels, get_languages, load_yaml_config, resolve_path
from c2_analyzer.dataset.manifest import freeze, verify
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.statistics import compute_statistics, read_page_facts
from c2_analyzer.dataset.stats_report import write_report
from c2_analyzer.dataset.views import VIEWS, select_view
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/dataset_stats.py stats
  python scripts/dataset_stats.py stats --view clean
  python scripts/dataset_stats.py freeze --version v0.1 --notes "after first full review"
  python scripts/dataset_stats.py verify --version v0.1
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

    stats = commands.add_parser("stats", help="write dataset_stats.json/.md and figures")
    stats.add_argument("--view", choices=VIEWS, help="only this view (default: all three)")

    frozen = commands.add_parser("freeze", help="save the clean view as a dataset version")
    frozen.add_argument("--version", required=True, help="e.g. v0.1 (never overwritten)")
    frozen.add_argument("--notes", help="free text stored in the manifest JSON")

    check = commands.add_parser("verify", help="check the files of a frozen version")
    check.add_argument("--version", required=True)
    return parser


def print_summary(stats: dict) -> None:
    """Clean label x language counts and the readiness lines."""
    labels, languages = get_labels(), get_languages()
    clean = stats["views"].get("clean")
    if clean:
        width = max(len(label) for label in labels) + 2
        print("Clean view (what the models will train on): label x language")
        print("".ljust(width) + "".join(f"{lang:>9}" for lang in languages) + f"{'total':>9}")
        for label in labels:
            row = clean["label_by_language"][label]
            cells = "".join(f"{row[lang]:>9}" for lang in languages)
            print(f"{label:<{width}}{cells}{clean['per_label'][label]:>9}")
        totals = "".join(f"{clean['per_language'][lang]:>9}" for lang in languages)
        print(f"{'total':<{width}}{totals}{clean['total']:>9}")
        print()

    readiness = stats["readiness"]
    print("Readiness (clean view vs configs/collection_targets.yaml):")
    for label, item in readiness["labels"].items():
        print(f"  {label:<18} {item['have']:>4}/{item['target']:<4} {item['status']}")
    for coverage in readiness["language_coverage"].values():
        print(
            f"  {coverage['name']} coverage: {coverage['samples']} sample(s), "
            f"{coverage['percent_of_clean']}% of the clean view"
        )
    print(f"Dataset version: {stats['dataset_version']}")


def cmd_stats(args: argparse.Namespace, store: MetadataStore, reports_dir: Path) -> int:
    views = (args.view,) if args.view else VIEWS
    if args.view and "clean" not in views:
        # The figures and the readiness check always use the clean view too.
        print("Note: figures and readiness always include the clean view.")
    df = store.df
    rows = df if "all" in views else select_view(df, "usable")  # clean is part of usable
    facts = read_page_facts(store, rows, show_progress=True)
    stats = compute_statistics(store, reports_dir, views=views, facts=facts)
    paths = write_report(stats, df, facts, reports_dir)

    print_summary(stats)
    print()
    print("Written:")
    for path in paths:
        print(f"  {path}")
    return 0


def cmd_freeze(args: argparse.Namespace, store: MetadataStore) -> int:
    csv_path, info = freeze(store, args.version, notes=args.notes)
    print(f"Froze dataset {info['version']}: {info['total']} clean sample(s)")
    for label, count in info["counts_per_label"].items():
        print(f"  {label}: {count}")
    print(f"git commit: {info['git_commit'] or 'unknown'}")
    print(f"Wrote {csv_path} and {csv_path.with_suffix('.json').name}")
    print("Commit the manifest so later results can name this version.")
    return 0


def cmd_verify(args: argparse.Namespace, store: MetadataStore) -> int:
    result = verify(store, args.version)
    if result.ok:
        print(f"Dataset {result.version}: all {result.checked} file(s) present and unchanged.")
        return 0
    print(f"Dataset {result.version}: {result.checked} file(s) checked - PROBLEMS:")
    if result.missing:
        print(f"  {len(result.missing)} missing (quarantined?): {', '.join(result.missing)}")
    if result.changed:
        print(f"  {len(result.changed)} changed (sha256 differs): {', '.join(result.changed)}")
    return 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = MetadataStore(args.metadata, args.raw_dir)
    reports_dir = args.reports_dir or resolve_path(
        Path(load_yaml_config("config")["dedup"]["reports_dir"])
    )
    try:
        if args.command == "stats":
            return cmd_stats(args, store, reports_dir)
        if args.command == "freeze":
            return cmd_freeze(args, store)
        return cmd_verify(args, store)
    except (ValueError, FileNotFoundError, FileExistsError, FileSaveError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
