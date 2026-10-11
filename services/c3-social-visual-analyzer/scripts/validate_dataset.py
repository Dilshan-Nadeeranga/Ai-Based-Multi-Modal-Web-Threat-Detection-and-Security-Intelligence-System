"""Validate data/annotations/dataset_metadata.jsonl and its referenced files.

    python scripts/validate_dataset.py            # human-readable report
    python scripts/validate_dataset.py --json     # machine-readable report

Exit code: 0 = no errors (warnings allowed), 1 = errors found.
"""

from __future__ import annotations

import argparse
import json
import sys

from _bootstrap import load_settings, setup

from app.exceptions import ServiceError
from app.services.dataset_validator import DatasetValidator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the multimodal dataset.")
    parser.add_argument("--data-dir", help="Alternative data directory")
    parser.add_argument("--skip-image-content", action="store_true",
                        help="Only check that image files exist (skip decoding them)")
    parser.add_argument("--json", action="store_true", help="Print the report as JSON")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    setup(args.verbose)

    try:
        report = DatasetValidator(load_settings(args.data_dir), not args.skip_image_content).validate()
    except ServiceError as exc:
        print(f"ERROR [{exc.code}]: {exc.message}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2))
    else:
        for finding in report.findings:
            where = " ".join(
                part for part in (
                    f"line {finding.line}" if finding.line else "",
                    finding.sample_id or "",
                ) if part
            )
            print(f"{finding.severity.upper():7} {finding.code:22} {where:20} {finding.message}")
        status = "VALID" if report.valid else "INVALID"
        print(
            f"\nDataset {status}: {report.records_checked} record line(s), {report.valid_records} schema-valid, "
            f"{report.error_count} error(s), {report.warning_count} warning(s)"
        )
    return 0 if report.valid else 1


if __name__ == "__main__":
    sys.exit(main())
