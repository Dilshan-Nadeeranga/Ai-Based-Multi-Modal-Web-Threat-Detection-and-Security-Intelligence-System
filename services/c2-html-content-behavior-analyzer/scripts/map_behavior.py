"""Map JS sources to sinks and build behavioral intent vectors.

Part 8: Behavioral intent mapping (sources -> sinks).
Thin CLI wrapper - all logic lives in ``c2_analyzer.behavior.dataflow``.
"""

from __future__ import annotations

import argparse

from c2_analyzer.behavior.dataflow import find_flows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input-dir", default="data/processed/js")
    parser.add_argument("--output-dir", default="data/processed/behavior")
    parser.parse_args()  # TODO (Part 8): read pages from --input-dir, write to --output-dir.
    find_flows(None)


if __name__ == "__main__":
    main()
