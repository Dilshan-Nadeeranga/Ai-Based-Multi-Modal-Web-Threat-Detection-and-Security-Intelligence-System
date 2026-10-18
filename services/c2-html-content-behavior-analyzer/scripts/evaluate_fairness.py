"""Fairness of the verdict on benign pages by subgroup (Sri Lankan SME / local, language).

Thin CLI wrapper - all logic lives in ``c2_analyzer.fusion.fairness``.

    python scripts/evaluate_fairness.py --version v0.3

Writes reports/fairness/<v>_fairness.{md,json}. Needs the fusion model, the stored arm
OOF / test probabilities and calibrate_verdict.py's thresholds; nothing is fetched.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.config import resolve_path
from c2_analyzer.fusion.fairness import evaluate, markdown
from c2_analyzer.utils.io import atomic_write_text, write_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--version", required=True, help="dataset version, e.g. v0.3")
    args = parser.parse_args(argv)
    result = evaluate(args.version)
    out = resolve_path(Path("reports/fairness"))
    write_json(result, out / f"{args.version}_fairness.json")
    text = markdown(result)
    atomic_write_text(text, out / f"{args.version}_fairness.md")
    print(f"wrote {out / f'{args.version}_fairness.md'}")
    for flag in result["flags"] or ["no subgroup flagged more than its reference"]:
        print(" -", flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
