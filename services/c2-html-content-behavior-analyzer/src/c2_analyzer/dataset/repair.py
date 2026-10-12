"""Repair: bring candidates.csv, metadata.csv and data/ back in line after a crash.

Part 1: Multilingual dataset preparation (Batch B).

Why: a fetch run saves metadata.csv and candidates.csv after every URL, but a
crash (or a locked file) between the two saves can leave them disagreeing.
This module finds those cases and fixes the safe ones:

  * candidate "fetched"/"duplicate" but its sample_id is not in metadata.csv
      -> reset to "pending" so it is fetched again
  * fetched page is in metadata.csv but its candidate is not "fetched"
      -> mark the candidate "fetched" with that sample_id
  * leftover temp files (data/tmp/*, *.tmp next to the CSVs)
      -> deleted
  * files in data/raw/ without a metadata row, or rows whose file is missing
      -> only REPORTED. Raw files are never deleted automatically; the user
         decides to register or delete them.

Do not run it while a fetch is running (it would delete that run's temp file).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from c2_analyzer.dataset.candidates import CandidateStore
from c2_analyzer.dataset.collection import temp_dir_for
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.utils.io import remove_quietly
from c2_analyzer.utils.url import normalize_url

# Candidate statuses that point at a sample in metadata.csv.
LINKED_STATUSES = ("fetched", "duplicate")


@dataclass
class RepairReport:
    """Everything repair found (and fixed, unless it was a dry run)."""

    reset_to_pending: list[str] = field(default_factory=list)  # candidate URLs
    relinked: list[tuple[str, str]] = field(default_factory=list)  # (URL, sample_id)
    temp_files: list[Path] = field(default_factory=list)  # removed (or to remove)
    locked_temp_files: list[Path] = field(default_factory=list)  # could not be removed
    orphan_raw_files: list[str] = field(default_factory=list)  # "<label>/<file>"
    missing_raw_files: list[str] = field(default_factory=list)  # sample_ids

    @property
    def is_clean(self) -> bool:
        return not any(
            (
                self.reset_to_pending,
                self.relinked,
                self.temp_files,
                self.locked_temp_files,
                self.orphan_raw_files,
                self.missing_raw_files,
            )
        )


def find_temp_files(candidates: CandidateStore, metadata: MetadataStore) -> list[Path]:
    """Leftover page temp files in data/tmp/ and atomic-write temp files next to the CSVs."""
    found: set[Path] = set()
    temp_dir = temp_dir_for(metadata)
    if temp_dir.is_dir():
        found |= {p for p in temp_dir.iterdir() if p.is_file() and p.name != ".gitkeep"}
    for csv_path in (candidates.csv_path, metadata.csv_path):
        # atomic_write_csv names them "<file>.<random>.tmp"
        found |= set(csv_path.parent.glob(f"{csv_path.name}.*.tmp"))
    return sorted(found)


def repair(
    candidates: CandidateStore, metadata: MetadataStore, dry_run: bool = False
) -> RepairReport:
    """Detect inconsistencies and fix the safe ones (see module docstring).

    With ``dry_run=True`` nothing is saved or deleted; the report shows what
    would change. metadata.csv is never modified.
    """
    report = RepairReport()
    df = candidates.df
    known_ids = set(metadata.df["sample_id"])

    # 1. Candidate points at a sample that was never saved -> fetch it again.
    lost = df[df["status"].isin(LINKED_STATUSES) & ~df["sample_id"].isin(known_ids)]
    for row in lost.to_dict("records"):
        missing = row["sample_id"] or "(none)"
        candidates.mark(
            row["url"],
            "pending",
            error=f"reset by repair: sample {missing} is not in metadata.csv",
            count_attempt=False,
        )
        report.reset_to_pending.append(row["url"])

    # 2. Page was saved but its candidate status was not -> link them.
    # Only rows written by the fetcher; hand-registered pages are left alone.
    fetched_rows = metadata.df[metadata.df["fetch_mode"].isin(("static", "rendered"))]
    sample_by_url: dict[str, str] = {}
    for row in fetched_rows.to_dict("records"):
        sample_by_url.setdefault(normalize_url(row["source_url"]), row["sample_id"])
    df = candidates.df
    unlinked = df[~df["status"].isin(LINKED_STATUSES)]
    for url in unlinked["url"]:
        sample_id = sample_by_url.get(normalize_url(url))
        if sample_id:
            candidates.mark(url, "fetched", error=None, sample_id=sample_id)
            report.relinked.append((url, sample_id))

    # 3. Temp files left behind by a crash.
    for path in find_temp_files(candidates, metadata):
        if dry_run or remove_quietly(path):
            report.temp_files.append(path)
        else:
            report.locked_temp_files.append(path)

    # 4. Report only: raw files without a row, rows without a file.
    report.orphan_raw_files = metadata.unregistered_files()
    for row in metadata.df.to_dict("records"):
        if not (metadata.raw_dir / row["file_path"]).is_file():
            report.missing_raw_files.append(row["sample_id"])

    if not dry_run and (report.reset_to_pending or report.relinked):
        candidates.save()
    return report
