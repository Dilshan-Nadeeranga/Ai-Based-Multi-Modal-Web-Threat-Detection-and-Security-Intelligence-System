"""Dataset versions: freeze the clean view into a manifest, and verify it later.

Part 1: Multilingual dataset preparation (Batch D, Task 13).

Why: the dataset keeps changing (new pages, reviews, relabels). Parts 2-6
must say exactly which dataset version they used, so a result in my thesis
can be reproduced months later. ``freeze`` writes the list of clean samples
with their sha256 to

    data/metadata/manifests/dataset_<version>.csv    sample_id, label, language,
                                                     cluster_id, sha256, file_path
    data/metadata/manifests/dataset_<version>.json   version, created_at, counts,
                                                     git commit, notes, fingerprint

and ``verify`` checks that every listed file still exists with the same
sha256. A version is never overwritten: a changed dataset gets a new version.

Manifests contain no URLs (only ids, labels, hashes and relative paths), so
they are safe to commit to git.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import pandas as pd

from c2_analyzer.config import get_labels, get_languages, project_root
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.views import select_view
from c2_analyzer.utils.hashing import sha256_file
from c2_analyzer.utils.io import atomic_write_csv

MANIFEST_COLUMNS = ["sample_id", "label", "language", "cluster_id", "sha256", "file_path"]
# v0.1, v1, v1.2.3 ... (also used in file names, so nothing else is allowed)
VERSION_PATTERN = re.compile(r"^v\d+(\.\d+)*$")


@dataclass
class VerifyResult:
    """Outcome of ``verify``: files that are gone or whose content changed."""

    version: str
    checked: int
    missing: list[str] = field(default_factory=list)  # sample ids
    changed: list[str] = field(default_factory=list)  # sample ids (sha256 differs)

    @property
    def ok(self) -> bool:
        return not self.missing and not self.changed


def manifests_dir(store: MetadataStore) -> Path:
    """Manifests live next to metadata.csv: data/metadata/manifests/."""
    return store.csv_path.parent / "manifests"


def manifest_paths(directory: Path, version: str) -> tuple[Path, Path]:
    """(csv, json) paths of one version."""
    if not VERSION_PATTERN.match(version):
        raise ValueError(f"invalid version {version!r}; use e.g. v0.1, v1.0 or v2")
    return directory / f"dataset_{version}.csv", directory / f"dataset_{version}.json"


def fingerprint(rows: pd.DataFrame) -> str:
    """One sha256 for a set of samples (ids, labels, languages and file hashes).

    Two datasets with the same fingerprint contain exactly the same files with
    the same labels, so the statistics can say "this is dataset v0.1".
    """
    lines = sorted(
        f"{row['sample_id']}|{row['label']}|{row['language']}|{row['sha256']}"
        for row in rows.to_dict("records")
    )
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def git_commit() -> str | None:
    """Current git commit hash (with "-dirty" if there are uncommitted changes), or None."""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root(),
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no", "."],
            cwd=project_root(),
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None  # git not installed or not a repository
    return f"{commit}-dirty" if status else commit or None


def counts(series: pd.Series, order: tuple[str, ...]) -> dict[str, int]:
    """Value counts in a fixed order (zeros included), so every report has the same keys."""
    found = series.value_counts()
    return {name: int(found.get(name, 0)) for name in order}


def check_files(raw_dir: Path, rows: pd.DataFrame) -> tuple[list[str], list[str]]:
    """Sample ids whose file is (missing, changed) - changed = sha256 differs."""
    missing, changed = [], []
    for row in rows.to_dict("records"):
        file = raw_dir / row["file_path"]
        if not file.is_file():
            missing.append(row["sample_id"])
        elif sha256_file(file) != row["sha256"]:
            changed.append(row["sample_id"])
    return missing, changed


def freeze(
    store: MetadataStore,
    version: str,
    notes: str | None = None,
    directory: Path | None = None,
) -> tuple[Path, dict]:
    """Write the manifest of the current clean view. Returns (csv path, info dict).

    Refuses to overwrite an existing version and refuses to freeze files that
    are missing or changed since they were registered (a frozen version must
    be complete and correct).
    """
    directory = directory or manifests_dir(store)
    csv_path, json_path = manifest_paths(directory, version)
    if csv_path.exists() or json_path.exists():
        raise FileExistsError(
            f"dataset {version} already exists ({csv_path.name}); versions are never "
            "overwritten - choose a new version number"
        )

    clean = select_view(store.df, "clean").sort_values("sample_id")
    if clean.empty:
        raise ValueError("the clean view is empty - nothing to freeze")
    missing, changed = check_files(store.raw_dir, clean)
    if missing or changed:
        raise ValueError(
            f"cannot freeze: {len(missing)} file(s) missing {missing[:5]}, "
            f"{len(changed)} file(s) changed {changed[:5]}. "
            "Run build_metadata.py validate and fix them first."
        )

    info = {
        "version": version,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "view": "clean",
        "total": len(clean),
        "counts_per_label": counts(clean["label"], get_labels()),
        "counts_per_language": counts(clean["language"], get_languages()),
        "fingerprint": fingerprint(clean),
        "git_commit": git_commit(),
        "notes": notes,
    }
    atomic_write_csv(clean, csv_path, MANIFEST_COLUMNS)
    json_path.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    return csv_path, info


def verify(store: MetadataStore, version: str, directory: Path | None = None) -> VerifyResult:
    """Check every file of a frozen version still exists with the same sha256."""
    csv_path, _ = manifest_paths(directory or manifests_dir(store), version)
    if not csv_path.exists():
        raise FileNotFoundError(f"no manifest for {version}: {csv_path}")
    manifest = pd.read_csv(csv_path, dtype=str, keep_default_na=False)

    missing, changed = check_files(store.raw_dir, manifest)
    return VerifyResult(version, len(manifest), missing, changed)


def list_versions(directory: Path) -> list[str]:
    """Frozen versions in this folder, oldest first (v0.2 before v0.10)."""
    versions = [path.stem.removeprefix("dataset_") for path in directory.glob("dataset_v*.json")]
    versions = [version for version in versions if VERSION_PATTERN.match(version)]
    return sorted(versions, key=lambda v: [int(part) for part in v[1:].split(".")])


def matching_version(directory: Path, clean: pd.DataFrame) -> str | None:
    """The frozen version whose samples are exactly the current clean view, if any."""
    current = fingerprint(clean)
    for version in reversed(list_versions(directory)):
        info = json.loads((directory / f"dataset_{version}.json").read_text(encoding="utf-8"))
        if info.get("fingerprint") == current:
            return version
    return None
