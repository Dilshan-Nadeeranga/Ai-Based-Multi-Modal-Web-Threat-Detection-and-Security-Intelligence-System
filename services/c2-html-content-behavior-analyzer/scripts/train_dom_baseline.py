"""Train LogReg / RandomForest / XGBoost DOM baselines.

Part 4: DOM baseline classifier (LogReg / RandomForest / XGBoost).
Thin CLI wrapper - all logic lives in ``c2_analyzer.classifiers.dom_baseline.train``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.classifiers.dom_baseline.train import train_all


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--features", default="data/processed/dom_features/dom_features.csv")
    parser.add_argument("--splits-dir", default="data/splits")
    parser.add_argument("--output-dir", default="models/dom_baseline")
    args = parser.parse_args()
    # TODO (Part 4): wire real arguments and output handling.
    train_all({}, Path(args.output_dir))


if __name__ == "__main__":
    main()
