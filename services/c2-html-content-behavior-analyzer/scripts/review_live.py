"""Review high-risk LIVE results in the terminal, then export confirmed ones to a
manual-feed CSV (Part 1 format) so they enter the dataset through the normal pipeline.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Why: C2's own verdicts are never training labels (confirmation bias). A person decides.
Shown as plain TEXT, URLs defanged (never opens a browser); each decision is saved at
once, so a review can be stopped and resumed. Logic: c2_analyzer.ingest.review.

  list     show the queue              python scripts/review_live.py list
  review   decide one by one           python scripts/review_live.py review --reviewer Dilshan
           keys: [c]onfirm C2's class  [r]elabel  [x] reject (not a threat / wrong)
                 [s]kip  [q]uit
  export   confirmed -> CSV            python scripts/review_live.py export
           default data/feeds/live_review_urls.csv (url,label,language_hint,source,notes),
           then: python scripts/collect.py import --feed manual --file <that csv>
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from c2_analyzer.config import get_labels, get_settings, project_root, resolve_path
from c2_analyzer.ingest.review import check_label, describe_item, export_confirmed
from c2_analyzer.store.repository import REVIEW_STATES, ResultsStore

DEFAULT_EXPORT = Path("data/feeds/live_review_urls.csv")


def ask_label(default: str | None) -> str | None:
    labels = get_labels()
    print("  labels: " + "  ".join(f"{i}={name}" for i, name in enumerate(labels)))
    answer = input(f"  label number{f' [{default}]' if default else ''}: ").strip()
    if not answer:
        return default
    if answer.isdigit() and int(answer) < len(labels):
        return labels[int(answer)]
    try:
        return check_label(answer)
    except ValueError as error:
        print(f"  {error}")
        return None


def cmd_list(store: ResultsStore, args) -> None:
    items = store.reviews(None if args.state == "all" else args.state, limit=args.limit)
    print(f"{len(items)} item(s); queue: {store.review_counts()}")
    for item in items:
        print()
        print(describe_item(item))
        if item["state"] != "pending":
            print(
                f"  decided:  {item['state']} {item['decided_label'] or ''} by "
                f"{item['decided_by']} at {item['decided_at']}"
            )


def cmd_review(store: ResultsStore, args) -> None:
    items = [
        i for i in store.reviews("pending", limit=args.limit) if args.include_demo or not i["demo"]
    ]
    print(f"{len(items)} pending item(s). Keys: [c]onfirm [r]elabel [x] reject [s]kip [q]uit")
    done = 0
    for item in items:
        print()
        print(describe_item(item))
        while True:
            key = input("  decision [c/r/x/s/q]: ").strip().lower()[:1]
            if key == "q":
                print(f"saved {done} decision(s)")
                return
            if key == "s":
                break
            if key in ("c", "r"):
                default = item["threat_class"] if key == "c" else None
                label = default if key == "c" and default else ask_label(default)
                if label is None:
                    continue
                store.decide_review(item["job_id"], "confirmed", label, args.reviewer)
                print(f"  confirmed as {label}")
                done += 1
                break
            if key == "x":
                store.decide_review(item["job_id"], "rejected", None, args.reviewer)
                print("  rejected (will not be exported)")
                done += 1
                break
            print("  unknown key")
    print(f"done: {done} decision(s); queue: {store.review_counts()}")


def cmd_export(store: ResultsStore, args) -> None:
    out = args.out if args.out.is_absolute() else project_root() / args.out
    report = export_confirmed(store, out, include_demo=args.include_demo)
    print(
        f"wrote {report.written} row(s) to {report.path} "
        f"({report.already_in_file} already in the file)"
    )
    if report.written:
        print(f"next: python scripts/collect.py import --feed manual --file {args.out}")


def main() -> None:
    os.chdir(project_root())
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0], formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--db", type=Path, help="results database (default RESULTS_DB)")
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("list", help="show the review queue")
    show.add_argument("--state", choices=[*REVIEW_STATES, "all"], default="pending")
    show.add_argument("--limit", type=int)
    review = commands.add_parser("review", help="decide pending items one by one")
    review.add_argument("--reviewer", required=True, help="your name (stored as decided_by)")
    review.add_argument("--limit", type=int)
    review.add_argument("--include-demo", action="store_true", help="also demo scans")
    export = commands.add_parser("export", help="confirmed items -> manual-feed CSV")
    export.add_argument("--out", type=Path, default=DEFAULT_EXPORT)
    export.add_argument("--include-demo", action="store_true", help="also demo scans")
    args = parser.parse_args()

    store = ResultsStore(args.db or resolve_path(get_settings().results_db))
    try:
        {"list": cmd_list, "review": cmd_review, "export": cmd_export}[args.command](store, args)
    finally:
        store.close()


if __name__ == "__main__":
    main()
