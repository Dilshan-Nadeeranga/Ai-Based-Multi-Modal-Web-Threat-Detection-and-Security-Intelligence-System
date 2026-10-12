"""Build data/metadata/metadata.csv from data/raw/.

Part 1: Multilingual dataset preparation.
Thin CLI wrapper - all logic lives in ``c2_analyzer.dataset.metadata``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.dataset.metadata import build_metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--output", default="data/metadata/metadata.csv")
    args = parser.parse_args()
    # TODO (Part 1): wire real arguments and output handling.
    build_metadata(Path(args.raw_dir))


if __name__ == "__main__":
    main()
