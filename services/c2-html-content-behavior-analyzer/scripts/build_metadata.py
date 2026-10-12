"""Manage the dataset index (data/metadata/metadata.csv) from the command line.

Part 1: Multilingual dataset preparation.

Why: collecting the dataset is manual, repeated work. This CLI makes the safe
way the easy way - registering a page copies it to the right folder, hashes
it and validates its metadata in one step. It is a thin wrapper; the logic is
in ``c2_analyzer.dataset.metadata`` and ``c2_analyzer.dataset.collector``.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from c2_analyzer.config import get_labels, get_languages, get_sources
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.metadata import MetadataStore

EXAMPLES = """examples:
  python scripts/build_metadata.py register --file page.html --label phishing \\
      --language en --source phishtank --source-url https://bad.example/login
  python scripts/build_metadata.py validate
  python scripts/build_metadata.py show --label phishing --language si
"""

# Columns printed by `show` (the full rows are too wide for a terminal).
SHOW_COLUMNS = ["sample_id", "label", "language", "source", "collection_date", "verified"]


def iso_date(text: str) -> date:
    """argparse type for YYYY-MM-DD dates."""
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid date {text!r}, expected YYYY-MM-DD") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--metadata", type=Path, help="metadata CSV (default: data/metadata/metadata.csv)"
    )
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default: data/raw)")
    commands = parser.add_subparsers(dest="command", required=True)

    register = commands.add_parser("register", help="copy an HTML file into data/raw and add it")
    register.add_argument("--file", type=Path, required=True, help="HTML file to register")
    register.add_argument("--label", required=True, choices=get_labels())
    register.add_argument("--language", required=True, choices=get_languages())
    register.add_argument("--source", required=True, choices=get_sources())
    register.add_argument("--source-url", required=True, help="original URL of the page")
    register.add_argument(
        "--date", type=iso_date, help="collection date YYYY-MM-DD (default: today)"
    )
    register.add_argument("--notes", help="free-text notes")

    commands.add_parser("validate", help="check every record and file; exit code 1 if problems")

    show = commands.add_parser("show", help="print matching records")
    show.add_argument("--label", choices=get_labels())
    show.add_argument("--language", choices=get_languages())
    return parser


def cmd_register(store: MetadataStore, args: argparse.Namespace) -> int:
    record, warnings = register_file(
        store,
        args.file,
        label=args.label,
        language=args.language,
        source=args.source,
        source_url=args.source_url,
        collection_date=args.date,
        notes=args.notes,
    )
    store.save()
    print(f"Registered {record.sample_id} -> data/raw/{record.file_path}")
    for warning in warnings:
        print(f"Warning: {warning}")
    return 0


def cmd_validate(store: MetadataStore) -> int:
    problems = store.validate_all()
    count = len(store.df)
    if not problems:
        print(f"OK - {count} record(s) checked, no problems found.")
        return 0
    print(f"Found {len(problems)} problem(s) in {count} record(s):")
    for problem in problems:
        print(f"  - {problem}")
    return 1


def cmd_show(store: MetadataStore, args: argparse.Namespace) -> int:
    rows = store.filter(label=args.label, language=args.language)
    if rows.empty:
        print("No matching records.")
    else:
        print(rows[SHOW_COLUMNS].to_string(index=False))
        print(f"\n{len(rows)} record(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = MetadataStore(args.metadata, args.raw_dir)
    try:
        if args.command == "register":
            return cmd_register(store, args)
        if args.command == "validate":
            return cmd_validate(store)
        return cmd_show(store, args)
    except (ValueError, FileNotFoundError, FileExistsError) as error:
        # Expected user errors (bad value, duplicate, missing file): short message, exit 1.
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
