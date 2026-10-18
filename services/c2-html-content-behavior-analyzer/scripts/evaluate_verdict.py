"""Part 9 B-1: verdict operating points (OOF + the 68 test pages) and /analyze latency.

Part 9: Batch B-1 - end-to-end URL analysis engine.
Thin CLI wrapper - all logic lives in ``c2_analyzer.fusion.verdict_eval``.

    python scripts/evaluate_verdict.py --version v0.3              # OOF + test with/without XLM-R
    python scripts/evaluate_verdict.py --version v0.3 --no-xlmr    # skip the XLM-R test run

Writes reports/verdict/<v>_operating_points.{md,json}. Run calibrate_verdict.py first.
"""

from __future__ import annotations

import argparse

from c2_analyzer.fusion.verdict import VerdictPolicy
from c2_analyzer.fusion.verdict_eval import evaluate_oof, evaluate_test, markdown, write_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--version", required=True, help="dataset version, e.g. v0.3")
    parser.add_argument("--no-xlmr", action="store_true", help="only the 3-arm test run")
    args = parser.parse_args(argv)
    policy = VerdictPolicy.load()
    arms = list(policy.calibration["fusion_arms"])
    configs = {"all arms": arms}
    if "text_xlmr" in arms:
        configs["without XLM-R"] = [arm for arm in arms if arm != "text_xlmr"]
    oof = evaluate_oof(args.version, configs)
    tests = []
    if not args.no_xlmr and "text_xlmr" in arms:
        tests.append(evaluate_test(args.version, xlmr=True))
    tests.append(evaluate_test(args.version, xlmr=False))
    text = markdown(args.version, oof, tests, policy.calibration)
    for path in write_report(args.version, oof, tests, policy.calibration):
        print(f"wrote {path}")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
