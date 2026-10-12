"""Write a sanitized, script-free copy of samples to look at their layout safely.

Part 1: Multilingual dataset preparation (Batch C, Task 12 helper).

Why: when the text shown by review_labels.py is not enough to decide a label,
this writes data/metadata/review/<sample_id>_safe.html with all scripts,
links, forms and outside resources removed (see
c2_analyzer.dataset.safe_preview). Open ONLY that _safe.html file - never the
original in data/raw/. The files are git-ignored.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.safe_preview import write_safe_preview


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sample_ids", nargs="+", help="e.g. c2_phishing_000001")
    parser.add_argument("--metadata", type=Path, help="metadata CSV (default data/metadata)")
    parser.add_argument("--raw-dir", type=Path, help="raw data folder (default data/raw)")
    parser.add_argument("--out-dir", type=Path, help="default data/metadata/review")
    args = parser.parse_args(argv)

    store = MetadataStore(args.metadata, args.raw_dir)
    status = 0
    for sample_id in args.sample_ids:
        try:
            path = write_safe_preview(store, sample_id, args.out_dir)
            print(f"Wrote {path}")
        except (KeyError, FileNotFoundError) as error:
            print(f"Error ({sample_id}): {error}", file=sys.stderr)
            status = 1
    print("Open only the *_safe.html files. Never open the originals in data/raw/.")
    return status


if __name__ == "__main__":
    sys.exit(main())
