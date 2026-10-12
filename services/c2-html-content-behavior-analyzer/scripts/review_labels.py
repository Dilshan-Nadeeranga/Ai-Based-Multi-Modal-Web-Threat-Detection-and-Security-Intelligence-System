"""Review sample labels in the terminal, and run the peer-verification check.

Part 1: Multilingual dataset preparation (Batch C, Task 12).

Why: every label must be checked by a person before training. This tool
shows one sample at a time as plain TEXT (it never opens a browser) and
saves each decision immediately, so a review can be stopped and resumed.
The logic lives in c2_analyzer.dataset.verifier.

  review       go through samples:  [c]onfirm [r]elabel [l]anguage e[x]clude [s]kip [b]ack [q]uit
  export-peer  random share of my verified samples for a second person (no labels shown)
  import-peer  agreement % and Cohen's kappa between their labels and mine
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.config import get_labels, get_languages, load_yaml_config, resolve_path
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.verifier import (
    ReviewSession,
    describe_kappa,
    export_peer_sheet,
    import_peer_sheet,
    select_samples,
)
from c2_analyzer.utils.io import FileSaveError

EXAMPLES = """examples:
  python scripts/review_labels.py review --reviewer Dilshan --label phishing
  python scripts/review_labels.py review --reviewer Dilshan --only-flagged
  python scripts/review_labels.py review --reviewer Dilshan --cluster-representatives-only \\
      --random --limit 50
  python scripts/review_labels.py export-peer --fraction 0.1 --seed 42
  python scripts/review_labels.py import-peer --file reports/dataset_stats/peer_review_sheet.csv
"""


def reports_dir() -> Path:
    return resolve_path(Path(load_yaml_config("config")["dedup"]["reports_dir"]))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    commands = parser.add_subparsers(dest="command", required=True)

    review = commands.add_parser("review", help="review samples one by one")
    review.add_argument("--reviewer", required=True, help="your name (stored as verified_by)")
    review.add_argument("--label", choices=get_labels())
    review.add_argument("--language", choices=get_languages())
    review.add_argument(
        "--only-unverified", action="store_true", default=True,
        help="skip verified/excluded samples (default)",
    )  # fmt: skip
    review.add_argument(
        "--include-verified", dest="only_unverified", action="store_false",
        help="also show samples that were already reviewed",
    )  # fmt: skip
    review.add_argument("--only-flagged", action="store_true", help="quality_flag is not ok")
    review.add_argument(
        "--cluster-representatives-only", action="store_true",
        help="skip pages marked as a near-duplicate of another page",
    )  # fmt: skip
    review.add_argument("--random", action="store_true", help="random order")
    review.add_argument("--seed", type=int, help="seed for --random (repeatable order)")
    review.add_argument("--limit", type=int, help="review at most N samples")

    export = commands.add_parser("export-peer", help="sheet for a second rater")
    export.add_argument("--fraction", type=float, default=0.1)
    export.add_argument("--seed", type=int, default=42)
    export.add_argument(
        "--out", type=Path, help="default reports/dataset_stats/peer_review_sheet.csv"
    )

    imp = commands.add_parser("import-peer", help="agreement with the peer's labels")
    imp.add_argument("--file", type=Path, required=True)
    imp.add_argument("--out", type=Path, help="default reports/dataset_stats/peer_agreement.json")
    return parser


def cmd_review(args: argparse.Namespace, store: MetadataStore) -> int:
    ids = select_samples(
        store,
        label=args.label,
        language=args.language,
        only_unverified=args.only_unverified,
        only_flagged=args.only_flagged,
        representatives_only=args.cluster_representatives_only,
        random_order=args.random,
        limit=args.limit,
        seed=args.seed,
    )
    print(f"{len(ids)} sample(s) to review. Every decision is saved immediately.")
    try:
        decisions = ReviewSession(store, args.reviewer, ids).run()
    except (KeyboardInterrupt, EOFError):
        print("\nStopped - all decisions so far are saved.")
        return 0
    print(f"{len(decisions)} decision(s) in this session.")
    return 0


def cmd_export(args: argparse.Namespace, store: MetadataStore) -> int:
    out = args.out or reports_dir() / "peer_review_sheet.csv"
    sheet = export_peer_sheet(store, out, fraction=args.fraction, seed=args.seed)
    print(f"Wrote {len(sheet)} sample(s) to {out}")
    print(f"Ask your peer to fill the peer_label column with one of: {', '.join(get_labels())}")
    print("Then: python scripts/review_labels.py import-peer --file <their file>")
    return 0


def cmd_import(args: argparse.Namespace, store: MetadataStore) -> int:
    out = args.out or reports_dir() / "peer_agreement.json"
    result = import_peer_sheet(store, args.file, out)
    kappa = "undefined" if result.cohen_kappa is None else f"{result.cohen_kappa:.3f}"
    print(f"Rated samples:    {result.rated}  (rows left empty: {result.unrated})")
    print(f"Agreement:        {result.agreement_percent:.1f}%")
    print(f"Cohen's kappa:    {kappa}  ({describe_kappa(result.cohen_kappa)})")
    if result.disagreements:
        print(f"Disagreements ({len(result.disagreements)}) - review these again:")
        for item in result.disagreements:
            print(f"  {item['sample_id']}: mine={item['my_label']} peer={item['peer_label']}")
    print(f"Saved {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Page text can be Sinhala/Tamil; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    store = MetadataStore(args.metadata, args.raw_dir)
    try:
        if args.command == "review":
            return cmd_review(args, store)
        if args.command == "export-peer":
            return cmd_export(args, store)
        return cmd_import(args, store)
    except (ValueError, KeyError, FileNotFoundError, FileExistsError, FileSaveError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
