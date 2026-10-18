"""Fill the results database with demo scans (v0.3 test pages) for the frontend.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Each v0.3 TEST page's saved HTML is analysed by the real engine in html mode (nothing is
fetched) and stored as source=threatradar_push, demo=true, spread over the last 24 h.
Logic: c2_analyzer.ingest.demo.

  python scripts/demo_ingest.py                    # all 68 test pages, XLM-R on
  python scripts/demo_ingest.py --count 20 --no-xlmr
  python scripts/demo_ingest.py --clear            # remove every demo row
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from c2_analyzer.config import get_settings, project_root, resolve_path
from c2_analyzer.ingest.demo import clear_demo, run_demo


def main() -> None:
    os.chdir(project_root())  # .env (RESULTS_DB) is read from the service folder
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", default="v0.3", help="dataset version (default v0.3)")
    parser.add_argument("--count", type=int, help="at most N test pages (default all)")
    parser.add_argument("--no-xlmr", action="store_true", help="3 arms (faster, no torch)")
    parser.add_argument("--spread-hours", type=float, default=24.0)
    parser.add_argument("--db", type=Path, help="results database (default RESULTS_DB)")
    parser.add_argument("--clear", action="store_true", help="delete demo rows and stop")
    args = parser.parse_args()

    db = args.db or resolve_path(get_settings().results_db)
    if args.clear:
        print(f"removed {clear_demo(db)} demo scan(s) from {db}")
        return
    print(f"Demo scans -> {db} (version {args.version}, html mode, nothing fetched)")
    started = time.perf_counter()
    verdicts = run_demo(
        db, args.version, args.count, xlmr=not args.no_xlmr, spread_hours=args.spread_hours
    )
    total = sum(verdicts.values())
    print(f"stored {total} demo scan(s) in {time.perf_counter() - started:.1f}s: {dict(verdicts)}")


if __name__ == "__main__":
    main()
