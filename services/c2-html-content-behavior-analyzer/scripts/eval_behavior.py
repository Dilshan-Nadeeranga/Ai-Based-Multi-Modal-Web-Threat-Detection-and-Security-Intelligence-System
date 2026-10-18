"""Behavioral intent detection rate on real, hand-labelled v0.3 pages (Part 8 evaluation).

Why: a thin wrapper around c2_analyzer.behavior.benchmark - reads
data/benchmarks/behavior_v1/candidates.csv and the STORED Part 8 results of the frozen
version, writes reports/behavior/benchmark_v1.{md,json}. Nothing is executed or fetched.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.behavior.benchmark import (
    MISS_NOTES,
    evaluate_cases,
    load_candidates,
    render_markdown,
    summarize,
)
from c2_analyzer.config import resolve_path
from c2_analyzer.utils.io import atomic_write_text, write_json


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--version", default="v0.3")
    ap.add_argument("--candidates", type=Path, default=None)
    ap.add_argument("--out-dir", type=Path, default=Path("reports/behavior"))
    args = ap.parse_args(argv)

    cases = evaluate_cases(load_candidates(args.candidates), args.version)
    summary = summarize(cases)
    out = resolve_path(args.out_dir)
    write_json({"version": args.version, **summary}, out / "benchmark_v1.json")
    atomic_write_text(
        render_markdown(summary, cases, args.version, MISS_NOTES), out / "benchmark_v1.md"
    )
    overall = summary["overall"]["any"]
    print(f"{summary['n_cases']} cases, TPR {overall['tpr']['text']}, FPR {overall['fpr']['text']}")
    print(f"-> {out / 'benchmark_v1.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
