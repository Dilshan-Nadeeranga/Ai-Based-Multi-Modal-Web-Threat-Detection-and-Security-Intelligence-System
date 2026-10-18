"""Daily backup pull: queue ThreatRadar URLs C2 has never seen (source=threatradar_pull).

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Reads ThreatRadar's output files (read-only) with the Part 1 parsers:
scraped/urls_only.csv (Telegram), scraped/reddit_urls_only.csv (Reddit),
filtered/filtered_domains_*.json (domain filter). Only QUEUES - the API's background
worker (python scripts/run_api.py) analyses the queue. Logic: c2_analyzer.ingest.pull.

  python scripts/pull_threatradar.py --dir ..\\..\\ingestion\\threat-radar\\backend\\data
  python scripts/pull_threatradar.py --dir <data> --since 2026-10-10 --limit 200

Run it once a day with Windows Task Scheduler: the one-line ``schtasks /Create ...``
command is in docs/threatradar_integration.md ("Daily backup pull").
"""

from __future__ import annotations

import argparse
import os
from datetime import date
from pathlib import Path

from c2_analyzer.config import get_settings, project_root, resolve_path
from c2_analyzer.dataset.feeds import THREATRADAR_SOURCES
from c2_analyzer.ingest.pull import pull_threatradar
from c2_analyzer.ingest.service import IngestService
from c2_analyzer.store.repository import ResultsStore


def parse_sources(text: str) -> tuple[str, ...]:
    names = tuple(name.strip() for name in text.split(",") if name.strip())
    unknown = [name for name in names if name not in THREATRADAR_SOURCES]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown source(s) {unknown}; choose from {','.join(THREATRADAR_SOURCES)}"
        )
    return names


def main() -> None:
    # resolve --dir before changing to the service folder (where .env is read)
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dir", type=Path, required=True, help="ingestion/threat-radar/backend/data folder"
    )
    parser.add_argument("--since", type=date.fromisoformat, help="only rows on/after YYYY-MM-DD")
    parser.add_argument(
        "--sources",
        type=parse_sources,
        default=THREATRADAR_SOURCES,
        help=f"comma list of {','.join(THREATRADAR_SOURCES)} (default all)",
    )
    parser.add_argument("--limit", type=int, help="queue at most N new URLs")
    parser.add_argument("--db", type=Path, help="results database (default RESULTS_DB)")
    args = parser.parse_args()
    data_dir = args.dir.resolve()
    db = args.db.resolve() if args.db else None
    os.chdir(project_root())
    db = db or resolve_path(get_settings().results_db)

    store = ResultsStore(db)
    try:
        report = pull_threatradar(
            data_dir, IngestService(store), args.since, args.sources, args.limit
        )
        queued = report.queued
        print(f"ThreatRadar pull from {data_dir} -> {db}")
        print(f"  rows read:        {report.read}")
        print(f"  queued (new):     {queued.accepted}")
        print(f"  duplicates:       {queued.duplicates} (analysed in the last 24 h)")
        print(f"  already known:    {queued.already_known}")
        print(f"  rejected:         {len(queued.rejected)} (invalid / allow-listed)")
        if args.since:
            print(f"  before --since:   {report.before_since}")
        if report.over_limit:
            print(f"  over --limit:     {report.over_limit} (next run)")
        for item in report.missing_files:
            print(f"  missing file:     {item}")
        for item in report.unreadable:
            print(f"  unreadable:       {item}")
        print(f"  queue depth now:  {store.queue_depth()}")
    finally:
        store.close()


if __name__ == "__main__":
    main()
