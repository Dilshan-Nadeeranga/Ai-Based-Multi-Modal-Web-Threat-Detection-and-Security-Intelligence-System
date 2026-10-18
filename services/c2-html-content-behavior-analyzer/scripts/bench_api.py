"""Latency (fetch + analysis, NFR1) and concurrency (NFR5) of /api/v1/analyze on this machine.

Thin CLI wrapper - all logic lives in ``c2_analyzer.fusion.perf`` (see its docstring for
why url mode is measured as fetch + html-mode analysis).

    python scripts/bench_api.py --version v0.3                  # everything (~10 min)
    python scripts/bench_api.py --version v0.3 --skip-fetch     # concurrency only (no network)
    python scripts/bench_api.py --version v0.3 --levels 1 5     # fewer levels

Fetches ONLY public benign dataset URLs (never the scam pages). Writes
reports/performance/<v>_performance.{md,json}; the benchmark server's results DB is a
throw-away file under data/tmp/ (the real history DB is never touched).
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from c2_analyzer.config import resolve_path
from c2_analyzer.fusion import perf
from c2_analyzer.utils.io import atomic_write_text, write_json


def _remove_db(path: Path) -> None:
    """Delete the throw-away DB; Windows keeps the file locked briefly after the kill."""
    for suffix in ("", "-wal", "-shm"):
        target = path.with_name(path.name + suffix)
        for _ in range(20):
            try:
                target.unlink(missing_ok=True)
                break
            except PermissionError:
                time.sleep(0.25)
        else:
            print(f"warning: could not delete {target} (still locked) - safe to delete later")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--version", required=True)
    parser.add_argument("--urls", type=int, default=20)
    parser.add_argument("--levels", type=int, nargs="+", default=[1, 5, 10, 20])
    parser.add_argument("--port", type=int, default=8092)
    parser.add_argument("--skip-fetch", action="store_true")
    parser.add_argument(
        "--render-only", action="store_true", help="re-write the .md from the saved .json"
    )
    parser.add_argument("--no-xlmr-runs-only", action="store_true", help="skip the XLM-R runs")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # cp1252 consoles
    configs = [False] if args.no_xlmr_runs_only else [True, False]
    out = resolve_path(Path("reports/performance"))
    if args.render_only:
        import json

        saved = json.loads((out / f"{args.version}_performance.json").read_text("utf-8"))
        saved["reading"] = perf.reading(saved)
        write_json(saved, out / f"{args.version}_performance.json")
        atomic_write_text(perf.markdown(saved), out / f"{args.version}_performance.md")
        print("\n".join(saved["reading"]))
        return 0

    result = {
        "version": args.version,
        "measured_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "machine": perf.machine(),
        "fetch": {
            "n_urls": 0,
            "ok": 0,
            "statuses": {},
            "fetch_ms": perf.latency_summary([]),
            "median_kb": None,
            "pages": [],
        },
        "end_to_end": [],
        "concurrency": [],
    }
    if not args.skip_fetch:
        print(f"(a) fetching {args.urls} benign URLs ...")
        pages = perf.fetch_pages(perf.benign_urls(args.version, args.urls))
        ok = [p for p in pages if p["html"]]
        statuses: dict[str, int] = {}
        for p in pages:
            statuses[p["status"]] = statuses.get(p["status"], 0) + 1
        result["fetch"] = {
            "n_urls": len(pages),
            "ok": len(ok),
            "statuses": statuses,
            "fetch_ms": perf.latency_summary([p["fetch_ms"] for p in ok]),
            "median_kb": round(statistics.median(p["bytes"] for p in ok) / 1024) if ok else None,
            "pages": [
                {k: p[k] for k in ("sample_id", "status", "reason", "fetch_ms", "bytes")}
                for p in pages
            ],
        }
        for xlmr in configs:
            print(f"    analysing fetched pages (xlmr={xlmr}) ...")
            result["end_to_end"].append(perf.analyse_fetched(args.version, pages, xlmr))
    db_dir = resolve_path(Path("data/tmp"))
    db_dir.mkdir(parents=True, exist_ok=True)
    for xlmr in configs:
        print(f"(b) concurrency xlmr={xlmr} ...")
        result["concurrency"].append(
            perf.concurrency(args.version, xlmr, args.levels, db_dir, args.port)
        )
        _remove_db(db_dir / f"bench_{'xlmr' if xlmr else 'noxlmr'}.db")
    result["reading"] = perf.reading(result)
    write_json(result, out / f"{args.version}_performance.json")
    atomic_write_text(perf.markdown(result), out / f"{args.version}_performance.md")
    print("\n".join(result["reading"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
