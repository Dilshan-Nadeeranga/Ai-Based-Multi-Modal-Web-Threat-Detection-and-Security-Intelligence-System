"""Build the multilingual text corpus from parsed pages.

Part 5: Multilingual scam content analyzer.
Thin CLI wrapper - all logic lives in ``c2_analyzer.content.corpus_builder``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from c2_analyzer.content.corpus_builder import build_corpus


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input-dir", default="data/processed/parsed_html")
    parser.add_argument("--corpus-dir", default="data/corpus")
    args = parser.parse_args()
    # TODO (Part 5): wire real arguments and output handling.
    build_corpus(Path(args.input_dir), Path(args.corpus_dir))


if __name__ == "__main__":
    main()
