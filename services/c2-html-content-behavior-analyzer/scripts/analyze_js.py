"""Run static JS analysis on parsed pages.

Part 7: Static JavaScript intent analyzer.
Thin CLI wrapper - all logic lives in ``c2_analyzer.js_analyzer.detectors``.
"""

from __future__ import annotations

import argparse

from c2_analyzer.js_analyzer.detectors import analyze_scripts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input-dir", default="data/processed/parsed_html")
    parser.add_argument("--output-dir", default="data/processed/js")
    parser.parse_args()  # TODO (Part 7): read pages from --input-dir, write to --output-dir.
    analyze_scripts([])


if __name__ == "__main__":
    main()
