"""Evaluate a fine-tuned XLM-R checkpoint (per-language + macro).

Part 6: XLM-R content classification.
Thin CLI wrapper - all logic lives in ``c2_analyzer.nlp.evaluate``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.nlp.evaluate import evaluate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--checkpoint", default="models/xlmr")
    parser.add_argument("--output-dir", default="reports/metrics")
    args = parser.parse_args()
    # TODO (Part 6): wire real arguments and output handling.
    evaluate(Path(args.checkpoint), None)


if __name__ == "__main__":
    main()
