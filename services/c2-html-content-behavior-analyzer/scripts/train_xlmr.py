"""Fine-tune XLM-R on the content corpus.

Part 6: XLM-R content classification.
Thin CLI wrapper - all logic lives in ``c2_analyzer.nlp.train``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.nlp.train import train


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="configs/config.yaml")
    parser.add_argument("--output-dir", default="models/xlmr")
    args = parser.parse_args()
    # TODO (Part 6): wire real arguments and output handling.
    train({}, Path(args.output_dir))


if __name__ == "__main__":
    main()
