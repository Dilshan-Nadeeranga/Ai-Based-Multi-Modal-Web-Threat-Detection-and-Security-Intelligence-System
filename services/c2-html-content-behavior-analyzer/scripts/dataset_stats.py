"""Compute dataset statistics and train/val/test splits.

Part 1: Multilingual dataset preparation.
Thin CLI wrapper - all logic lives in ``c2_analyzer.dataset.statistics``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.dataset.statistics import compute_statistics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--metadata", default="data/metadata/metadata.csv")
    parser.add_argument("--output-dir", default="reports/dataset_stats")
    args = parser.parse_args()
    # TODO (Part 1): wire real arguments and output handling.
    compute_statistics(Path(args.metadata))


if __name__ == "__main__":
    main()
