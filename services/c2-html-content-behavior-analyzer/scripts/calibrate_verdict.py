"""Part 9 B-1: choose the verdict tier thresholds on the 9A out-of-fold predictions.

Part 9: Batch B-1 - end-to-end URL analysis engine.
Thin CLI wrapper - all logic lives in ``c2_analyzer.fusion.calibration``.

    python scripts/calibrate_verdict.py --version v0.3            # writes configs/verdict.yaml
    python scripts/calibrate_verdict.py --version v0.3 --dry-run  # print only

Re-run after every ``run_ablation.py`` (the API refuses thresholds made for another
fusion model). Then ``scripts/evaluate_verdict.py`` reports the operating points.
"""

from __future__ import annotations

import argparse
import sys

from c2_analyzer.fusion.calibration import calibrate, write_verdict_config
from c2_analyzer.fusion.verdict import VerdictPolicy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--version", required=True, help="dataset version, e.g. v0.3")
    parser.add_argument("--dry-run", action="store_true", help="do not write verdict.yaml")
    args = parser.parse_args(argv)
    result = calibrate(args.version, VerdictPolicy.load().tiers)
    if not result["calibration"]["reproduces_9a_threshold"]:
        print(
            "the full-arm OOF does not reproduce Part 9A - check the fusion inputs", file=sys.stderr
        )
    if args.dry_run:
        return 0
    path = write_verdict_config(result)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
