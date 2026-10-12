"""Extract DOM security features from parsed pages.

Part 3: DOM structural analysis.
Thin CLI wrapper - all logic lives in ``c2_analyzer.dom.exporter``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.dom.exporter import export_csv


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input-dir", default="data/processed/parsed_html")
    parser.add_argument("--output-dir", default="data/processed/dom_features")
    args = parser.parse_args()
    # TODO (Part 3): wire real arguments and output handling.
    export_csv([], Path(args.output_dir) / "dom_features.csv")


if __name__ == "__main__":
    main()
