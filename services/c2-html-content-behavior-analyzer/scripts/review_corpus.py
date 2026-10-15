"""Verify the scam-text corpus in the terminal, and run the peer-agreement check.

Part 5: Multilingual scam content analyzer (Batch B, Task 14).

Why: page segments are only weak-labelled by cue words; every text that is used
for validation / test must be checked by a person. This tool shows one text at a
time as plain TEXT and saves each decision immediately to
data/corpus/review/corpus_reviews.csv, so a review can be stopped and resumed
(a rebuild of the corpus keeps the decisions). Logic: c2_analyzer.content.corpus_review.

  review       [c]onfirm  change [i]ntents  [l]anguage  e[x]clude  [s]kip  [b]ack  [q]uit
  export-peer  random share of my verified texts per language for a second person (no labels)
  import-peer  agreement % and Cohen's kappa (overall + per language)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.content.corpus import CorpusPaths, ReviewStore, load_corpus
from c2_analyzer.content.corpus_review import (
    REVIEW_LANGUAGES,
    CorpusReviewSession,
    export_peer_sheet,
    import_peer_sheet,
    select_rows,
)
from c2_analyzer.content.taxonomy import intent_names
from c2_analyzer.utils.io import FileSaveError

SOURCE_TYPES = ["page_segment", "real_message", "synthetic_template", "machine_translation"]
EXAMPLES = """examples:
  python scripts/review_corpus.py review --reviewer Dilshan --language si
  python scripts/review_corpus.py review --reviewer Dilshan --needs-review
  python scripts/review_corpus.py review --reviewer Dilshan --split test \\
      --source-type page_segment --random --seed 1 --limit 50
  python scripts/review_corpus.py export-peer --fraction 0.1 --seed 42
  python scripts/review_corpus.py import-peer --file data/corpus/review/corpus_peer_sheet.csv
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    review = commands.add_parser("review", help="review corpus texts one by one")
    review.add_argument("--reviewer", required=True, help="your name (stored as verified_by)")
    review.add_argument("--language", choices=REVIEW_LANGUAGES)
    review.add_argument("--source-type", choices=SOURCE_TYPES)
    review.add_argument("--intent", choices=intent_names(), help="rows that carry this intent")
    review.add_argument("--split", choices=["train", "val", "test"])
    review.add_argument(
        "--only-unverified",
        action="store_true",
        default=True,
        help="skip verified / excluded texts (default)",
    )
    review.add_argument(
        "--include-verified",
        dest="only_unverified",
        action="store_false",
        help="also show texts that were already reviewed",
    )
    review.add_argument("--needs-review", action="store_true", help="only rows flagged for review")
    review.add_argument("--random", action="store_true", help="random order")
    review.add_argument("--seed", type=int, help="seed for --random (repeatable order)")
    review.add_argument("--limit", type=int, help="review at most N texts")

    export = commands.add_parser("export-peer", help="sheet for a second rater")
    export.add_argument("--fraction", type=float, default=0.1)
    export.add_argument("--seed", type=int, default=42)
    export.add_argument("--out", type=Path, help="default data/corpus/review/corpus_peer_sheet.csv")

    imp = commands.add_parser("import-peer", help="agreement with the peer's intents")
    imp.add_argument("--file", type=Path, required=True)
    imp.add_argument("--out", type=Path, help="default reports/content/corpus_peer_agreement.json")
    return parser


def cmd_review(args: argparse.Namespace, paths: CorpusPaths) -> int:
    frame = load_corpus(paths)
    ids = select_rows(
        frame,
        language=args.language,
        source_type=args.source_type,
        intent=args.intent,
        split=args.split,
        only_unverified=args.only_unverified,
        needs_review=args.needs_review,
        random_order=args.random,
        seed=args.seed,
        limit=args.limit,
    )
    print(f"{len(ids)} text(s) to review. Every decision is saved immediately.")
    session = CorpusReviewSession(frame, ReviewStore(paths.reviews_csv), args.reviewer, ids)
    try:
        decisions = session.run()
    except (KeyboardInterrupt, EOFError):
        print("\nStopped - all decisions so far are saved.")
        return 0
    print(f"{len(decisions)} decision(s) in this session. Run build_text_corpus.py stats to see")
    print("the verified share (a rebuild is not needed).")
    return 0


def cmd_export(args: argparse.Namespace, paths: CorpusPaths) -> int:
    out = args.out or paths.review_dir / "corpus_peer_sheet.csv"
    sheet = export_peer_sheet(load_corpus(paths), out, fraction=args.fraction, seed=args.seed)
    print(
        f"Wrote {len(sheet)} text(s) to {out} (per language: "
        f"{sheet['language'].value_counts().to_dict()})"
    )
    print(f"Ask your peer to fill peer_primary_intent with one of: {', '.join(intent_names())}")
    print("(peer_intents is optional.) The sheet holds corpus text: share it privately.")
    print("Then: python scripts/review_corpus.py import-peer --file <their file>")
    return 0


def cmd_import(args: argparse.Namespace, paths: CorpusPaths) -> int:
    out = args.out or paths.reports_dir / "corpus_peer_agreement.json"
    report = import_peer_sheet(load_corpus(paths), args.file, out)

    def line(name: str, block: dict) -> str:
        kappa = "undefined" if block["cohen_kappa"] is None else f"{block['cohen_kappa']:.3f}"
        return (
            f"  {name:<8} rated {block['rated']:>4}  agreement {block['agreement_percent']:>6.1f}%"
            f"  kappa {kappa} ({block['kappa_interpretation']})"
        )

    print(f"Rows left empty: {report['unrated_rows']}")
    print(line("all", report))
    for language, block in report["per_language"].items():
        print(line(language, block))
    if report["disagreements"]:
        print(f"Disagreements ({len(report['disagreements'])}) - review these again:")
        for item in report["disagreements"]:
            print(
                f"  {item['text_id']} [{item['language']}]: mine={item['my_intent']} "
                f"peer={item['peer_intent']}"
            )
    print(f"Saved {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Corpus text is Sinhala / Tamil too; never crash on a console that cannot show it.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    paths = CorpusPaths.from_config()
    commands = {"review": cmd_review, "export-peer": cmd_export, "import-peer": cmd_import}
    try:
        return commands[args.command](args, paths)
    except (ValueError, KeyError, FileNotFoundError, FileSaveError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
