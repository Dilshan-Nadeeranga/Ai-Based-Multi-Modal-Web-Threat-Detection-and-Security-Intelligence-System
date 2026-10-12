"""Dataset statistics: what is in the dataset, how clean it is, and is it ready.

Part 1: Multilingual dataset preparation (Batch D, Task 13).

Why: before any model is trained I must show (in the progress report and the
viva) how many samples each class and language has, how much was removed as
bad or duplicate, how much was checked by a person, and whether the targets
in configs/collection_targets.yaml are met. This module computes all of that
from metadata.csv (plus a light look at each page) and writes:

    reports/dataset_stats/dataset_stats.json   machine-readable, everything
    reports/dataset_stats/dataset_stats.md     tables to paste into the report
    reports/dataset_stats/figures/*.png        charts (see stats_figures.py)

The three views (defined in views.py):

- "all":    every row in metadata.csv
- "usable": not excluded AND quality_flag in (ok, redirected_offsite)
- "clean":  usable AND is_duplicate_of is null (one row per cluster) -
            this is what models will train on

Page statistics reuse page_view.parse_page (title/text/forms/scripts only);
the real feature extraction comes in Parts 2 and 3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from tqdm import tqdm

from c2_analyzer.config import (
    get_labels,
    get_languages,
    get_quality_flags,
    get_sources,
    load_yaml_config,
)
from c2_analyzer.dataset.manifest import (
    counts,
    fingerprint,
    list_versions,
    manifests_dir,
    matching_version,
)
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dataset.page_view import parse_page, read_html
from c2_analyzer.dataset.views import VIEWS, select_view

VIEW_DEFINITIONS = {
    "all": "every row in metadata.csv",
    "usable": "not excluded AND quality_flag in (ok, redirected_offsite)",
    "clean": "usable AND is_duplicate_of is empty (one row per cluster) - used for training",
}
FETCH_MODES = ("static", "rendered", "manual")
TOP_CLUSTERS = 10
# Languages whose coverage the readiness check reports separately.
LOCAL_LANGUAGES = {"si": "Sinhala", "ta": "Tamil"}


# ---- reading the pages (once) ------------------------------------------------------------------


@dataclass
class PageFacts:
    """The few facts about one saved page that the statistics need."""

    file_size: int  # bytes on disk
    text_chars: int  # visible text length
    forms: int
    has_password: bool
    has_script: bool


def read_page_facts(
    store: MetadataStore, rows: pd.DataFrame, show_progress: bool = False
) -> dict[str, PageFacts]:
    """Parse each page of ``rows`` once. Missing files are left out of the result."""
    facts = {}
    records = rows.to_dict("records")
    for row in tqdm(records, desc="Reading pages", unit="page", disable=not show_progress):
        path = store.raw_dir / row["file_path"]
        if not path.is_file():
            continue  # quarantined/deleted: reported as missing_files
        view = parse_page(read_html(path))
        facts[row["sample_id"]] = PageFacts(
            file_size=path.stat().st_size,
            text_chars=len(view.text),
            forms=len(view.forms),
            has_password=view.has_password_field,
            has_script=view.script_count > 0,
        )
    return facts


# ---- small helpers -----------------------------------------------------------------------------


def percent(part: int | float, whole: int | float) -> float:
    """part / whole in %, rounded to 1 decimal (0 when whole is 0)."""
    return round(100 * part / whole, 1) if whole else 0.0


def quantile(values: list[float], q: float) -> float | None:
    """The q-quantile (0.5 = median, 0.9 = p90), or None for an empty list."""
    return None if not values else round(float(pd.Series(values).quantile(q)), 1)


def crosstab(
    df: pd.DataFrame, rows: str, columns: str, row_order: tuple, column_order: tuple
) -> dict[str, dict[str, int]]:
    """Counts of ``rows`` x ``columns`` as {row: {column: n}}, zeros included."""
    table = pd.crosstab(df[rows], df[columns]) if not df.empty else pd.DataFrame()
    table = table.reindex(index=list(row_order), columns=list(column_order), fill_value=0)
    return {r: {c: int(table.loc[r, c]) for c in column_order} for r in row_order}


# ---- statistics of one view --------------------------------------------------------------------


def verification_stats(df: pd.DataFrame) -> dict[str, dict]:
    """Per label: verified, unverified and % verified."""
    result = {}
    for label in get_labels():
        rows = df[df["label"] == label]
        verified = int((rows["verified"] == "true").sum())
        result[label] = {
            "verified": verified,
            "unverified": len(rows) - verified,
            "percent_verified": percent(verified, len(rows)),
        }
    return result


def cluster_stats(df: pd.DataFrame) -> dict[str, Any]:
    """Number of clusters, the largest near-duplicate groups, duplicates per label.

    Sizes count only the rows of this view. Only groups with 2+ pages are
    listed as "largest" (a single page is not a near-duplicate group).
    """
    with_cluster = df[df["cluster_id"] != ""]
    sizes = with_cluster.groupby("cluster_id").size()
    ordered = sorted(sizes.items(), key=lambda item: (-item[1], item[0]))
    largest = []
    for cluster_id, size in ordered[:TOP_CLUSTERS]:
        if size < 2:
            break
        labels = sorted(set(with_cluster.loc[with_cluster["cluster_id"] == cluster_id, "label"]))
        largest.append({"cluster_id": cluster_id, "label": "+".join(labels), "size": int(size)})
    duplicates = df[df["is_duplicate_of"] != ""]
    return {
        "clusters": int(len(sizes)),
        "multi_page_clusters": int((sizes > 1).sum()),
        "rows_without_cluster": int(len(df) - len(with_cluster)),  # dedup not run yet
        "largest": largest,
        "duplicates_per_label": counts(duplicates["label"], get_labels()),
    }


def relabel_stats(df: pd.DataFrame) -> dict[str, Any]:
    """How many samples a reviewer moved to another label: {label_original: {label: n}}."""
    changed = df[df["label_original"] != ""]
    matrix: dict[str, dict[str, int]] = {}
    for (original, new), group in changed.groupby(["label_original", "label"]):
        matrix.setdefault(original, {})[new] = len(group)
    return {"relabelled": int(len(changed)), "matrix": matrix}


def imbalance(per_label: dict[str, int]) -> dict[str, Any]:
    """Majority/minority ratio and each class's share of the total.

    The ratio is None when a class has no samples at all (infinitely imbalanced).
    """
    total = sum(per_label.values())
    if total == 0:
        return {"majority": None, "minority": None, "ratio": None, "percent": {}}
    majority = max(per_label, key=per_label.get)
    minority = min(per_label, key=per_label.get)
    ratio = per_label[majority] / per_label[minority] if per_label[minority] else None
    return {
        "majority": majority,
        "minority": minority,
        "ratio": None if ratio is None else round(ratio, 2),
        "percent": {label: percent(count, total) for label, count in per_label.items()},
    }


def page_stats(df: pd.DataFrame, facts: dict[str, PageFacts]) -> dict[str, dict]:
    """Per label: file size and text length (median, p90), forms, % password, % script."""
    result = {}
    for label in get_labels():
        ids = df.loc[df["label"] == label, "sample_id"]
        pages = [facts[sample_id] for sample_id in ids if sample_id in facts]
        result[label] = {
            "pages": len(pages),
            "missing_files": int(len(ids) - len(pages)),
            "file_size_median": quantile([p.file_size for p in pages], 0.5),
            "file_size_p90": quantile([p.file_size for p in pages], 0.9),
            "text_chars_median": quantile([p.text_chars for p in pages], 0.5),
            "text_chars_p90": quantile([p.text_chars for p in pages], 0.9),
            "forms_mean": round(sum(p.forms for p in pages) / len(pages), 2) if pages else None,
            "percent_with_password": percent(sum(p.has_password for p in pages), len(pages)),
            "percent_with_script": percent(sum(p.has_script for p in pages), len(pages)),
        }
    return result


def timeline(df: pd.DataFrame) -> dict[str, dict[str, int]]:
    """Samples per collection_date per label, oldest date first."""
    dates = tuple(sorted(set(df["collection_date"])))
    return crosstab(df, "collection_date", "label", dates, get_labels())


def view_statistics(df: pd.DataFrame, facts: dict[str, PageFacts]) -> dict[str, Any]:
    """Every statistic for the rows of one view."""
    labels, languages = get_labels(), get_languages()
    per_label = counts(df["label"], labels)
    excluded = df[df["excluded"] == "true"]
    return {
        "total": len(df),
        "per_label": per_label,
        "per_language": counts(df["language"], languages),
        "label_by_language": crosstab(df, "label", "language", labels, languages),
        "per_source": counts(df["source"], get_sources()),
        "per_fetch_mode": counts(df["fetch_mode"], FETCH_MODES),
        "verification": verification_stats(df),
        "quality_flags": counts(df["quality_flag"], get_quality_flags()),
        "excluded": len(excluded),
        "excluded_by_reason": {
            reason: int(n) for reason, n in excluded["exclusion_reason"].value_counts().items()
        },
        "clusters": cluster_stats(df),
        "relabels": relabel_stats(df),
        "imbalance": imbalance(per_label),
        "page_stats": page_stats(df, facts),
        "timeline": timeline(df),
    }


# ---- readiness and peer agreement --------------------------------------------------------------


def readiness(clean: pd.DataFrame, targets: dict | None = None) -> dict[str, Any]:
    """Compare the CLEAN view with configs/collection_targets.yaml.

    Each label gets "ready" or what is missing, e.g. "12 more needed, 5 more si needed".
    """
    if targets is None:
        targets = load_yaml_config("collection_targets")
    per_language = targets.get("per_language", {})
    labels = {}
    for label in get_labels():
        rows = clean[clean["label"] == label]
        target = int(targets["overall"].get(label, 0))
        missing = []
        if len(rows) < target:
            missing.append(f"{target - len(rows)} more needed")
        languages = {}
        for language, language_targets in per_language.items():
            have = int((rows["language"] == language).sum())
            need = int(language_targets.get(label, 0))
            languages[language] = {"have": have, "target": need}
            if have < need:
                missing.append(f"{need - have} more {language} needed")
        labels[label] = {
            "have": len(rows),
            "target": target,
            "languages": languages,
            "ready": not missing,
            "status": ", ".join(missing) or "ready",
        }

    coverage = {}
    for language, name in LOCAL_LANGUAGES.items():
        rows = clean[clean["language"] == language]
        coverage[language] = {
            "name": name,
            "samples": len(rows),
            "percent_of_clean": percent(len(rows), len(clean)),
            "per_label": counts(rows["label"], get_labels()),
        }
    return {
        "all_ready": all(item["ready"] for item in labels.values()),
        "labels": labels,
        "language_coverage": coverage,
        "mixed_language_samples": int((clean["language"] == "mixed").sum()),
    }


def peer_summary(path: Path) -> dict[str, Any] | None:
    """Short summary of peer_agreement.json (written by review_labels.py import-peer)."""
    if not path.is_file():
        return None
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return {"error": f"could not read {path.name}: {error}"}
    return {
        "rated_samples": report.get("rated_samples"),
        "agreement_percent": report.get("agreement_percent"),
        "cohen_kappa": report.get("cohen_kappa"),
        "kappa_interpretation": report.get("kappa_interpretation"),
        "disagreements": len(report.get("disagreements", [])),
    }


# ---- everything together -----------------------------------------------------------------------


def compute_statistics(
    store: MetadataStore,
    reports_dir: Path,
    views: tuple[str, ...] = VIEWS,
    facts: dict[str, PageFacts] | None = None,
    show_progress: bool = False,
) -> dict[str, Any]:
    """All statistics as one JSON-ready dict (see the module docstring).

    ``facts`` can be passed in when the pages were already read (they are
    also needed for the figures), otherwise every page is read here.
    """
    df = store.df
    clean = select_view(df, "clean")
    if facts is None:
        facts = read_page_facts(store, df, show_progress)

    directory = manifests_dir(store)
    versions = list_versions(directory) if directory.is_dir() else []
    version = matching_version(directory, clean) if versions else None
    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        # The frozen version that matches the current clean view exactly,
        # or "unfrozen" while the dataset is still being collected/reviewed.
        "dataset_version": version or "unfrozen",
        "latest_frozen_version": versions[-1] if versions else None,
        "clean_fingerprint": fingerprint(clean),
        "definitions": {view: VIEW_DEFINITIONS[view] for view in views},
        "views": {view: view_statistics(select_view(df, view), facts) for view in views},
        "readiness": readiness(clean),
        "peer_agreement": peer_summary(reports_dir / "peer_agreement.json"),
    }
