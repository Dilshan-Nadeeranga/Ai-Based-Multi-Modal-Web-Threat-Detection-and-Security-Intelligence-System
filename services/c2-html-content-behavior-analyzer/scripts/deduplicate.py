"""Remove exact/near duplicates (data/raw -> data/interim).

Part 1: Multilingual dataset preparation.
Thin CLI wrapper - all logic lives in ``c2_analyzer.dataset.deduplicator``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.dataset.deduplicator import deduplicate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--raw-dir", default="data/raw")
    parser.add_argument("--interim-dir", default="data/interim")
    args = parser.parse_args()
    # TODO (Part 1): wire real arguments and output handling.
    deduplicate(Path(args.raw_dir), Path(args.interim_dir))


if __name__ == "__main__":
    main()
