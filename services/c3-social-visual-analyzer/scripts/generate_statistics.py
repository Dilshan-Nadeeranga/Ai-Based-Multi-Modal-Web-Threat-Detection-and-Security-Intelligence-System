"""Compute dataset statistics and write data/statistics/dataset_statistics.json.

    python scripts/generate_statistics.py
    python scripts/generate_statistics.py --include-synthetic --data-dir <demo dir>
"""

from __future__ import annotations

import argparse
import json
import sys

from _bootstrap import load_settings, setup

from app.exceptions import ServiceError
from app.services.statistics_service import DatasetStatistics, StatisticsService


def _print_summary(stats: DatasetStatistics) -> None:
    def nonzero(mapping: dict[str, int]) -> str:
        items = [f"{key}={value}" for key, value in mapping.items() if value]
        return ", ".join(items) or "none"

    print(f"Dataset version        : {stats.dataset_version}")
    print(f"Total samples          : {stats.total_samples}"
          + (" (synthetic included)" if stats.includes_synthetic else ""))
    if stats.excluded_synthetic_samples:
        print(f"Excluded synthetic     : {stats.excluded_synthetic_samples}")
    if stats.skipped_invalid_records or stats.malformed_lines:
        print(f"Skipped invalid/malformed: {stats.skipped_invalid_records}/{stats.malformed_lines} "
              "(run scripts/validate_dataset.py)")
    b = stats.binary_labels
    print(f"Legitimate / Scam      : {b.legitimate} / {b.scam}"
          + (f" (undecided {b.undecided})" if b.undecided else "")
          + (f" ({b.not_annotated} without scam label)" if b.not_annotated else ""))
    print(f"Class balance          : {stats.class_balance.legitimate_percent}% legitimate, "
          f"{stats.class_balance.scam_percent}% scam")
    print(f"Scam types             : {nonzero(stats.class_distribution)}")
    m = stats.misinformation_labels
    print(f"Real / Fake (news)     : {m.real} / {m.fake}"
          + (f" (undecided {m.undecided})" if m.undecided else "")
          + (f" ({m.not_annotated} without misinformation label)" if m.not_annotated else ""))
    print(f"Misinformation balance : {stats.misinformation_balance.real_percent}% real, "
          f"{stats.misinformation_balance.fake_percent}% fake")
    print(f"Misinformation types   : {nonzero(stats.misinformation_type_distribution)}")
    print(f"Platforms              : {nonzero(stats.platform_distribution)}")
    print(f"Label status (scam)    : {nonzero(stats.label_status)}")
    print(f"Label status (misinfo) : {nonzero(stats.misinformation_label_status)}")
    print(f"Images                 : {stats.total_images} total; {stats.samples_with_images} samples with, "
          f"{stats.samples_without_images} without, {stats.samples_with_multiple_images} with several")
    print(f"Embedded URLs          : {stats.total_embedded_urls} total; {stats.samples_with_urls} samples with, "
          f"{stats.samples_without_urls} without, {stats.samples_with_multiple_urls} with several")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate dataset statistics.")
    parser.add_argument("--data-dir", help="Alternative data directory")
    parser.add_argument("--include-synthetic", action="store_true",
                        help="Count synthetic_test samples (for demo/test data only)")
    parser.add_argument("--json", action="store_true", help="Print the statistics JSON")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    setup(args.verbose)

    settings = load_settings(args.data_dir)
    try:
        stats = StatisticsService(settings).generate(include_synthetic=args.include_synthetic)
    except ServiceError as exc:
        print(f"ERROR [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(stats.model_dump(mode="json"), ensure_ascii=False, indent=2))
    else:
        _print_summary(stats)
    print(f"\nWritten to data/statistics/{settings.dataset_statistics_path.name}"
          if not args.data_dir else f"\nWritten to {settings.dataset_statistics_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
