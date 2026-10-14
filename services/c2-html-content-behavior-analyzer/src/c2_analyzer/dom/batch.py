"""Extract DOM features for a whole frozen dataset version (Part 3 batch run).

Part 3: DOM structural analysis.

Why: Part 4 must train on exactly the pages of one frozen dataset version,
each processed once. For every manifest sample this:
  1. reads the raw HTML (decoded and size-capped exactly as Part 2 does);
  2. loads the stored Part 2 ParsedPage - or runs Part 2 and SAVES it if it is
     missing or stale, so Part 2's outputs stay complete;
  3. extracts the features and writes <sample_id>.json (DomResult + evidence);
then writes dom_features.csv (the Part 4 input) and feature_dictionary.json.

Rules (same as Part 2's batch):
- the manifest is verified first (files present, sha256 unchanged);
- a sample is skipped when its DomResult exists with the same source sha256,
  feature dictionary hash, and is newer than its ParsedPage (``force`` redoes);
- parallel worker processes ("spawn") via Part 2's ``run_tasks``;
- one broken page is "failed" and never stops the batch (it is left out of
  the CSV and listed in the report).
"""

from __future__ import annotations

import time
from pathlib import Path

import pandas as pd

from c2_analyzer.config import load_yaml_config
from c2_analyzer.dataset.manifest import manifest_paths, manifests_dir, verify
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.dom.dictionary import dictionary_hash, load_dictionary
from c2_analyzer.dom.exporter import (
    CSV_NAME,
    DICTIONARY_NAME,
    export_csv,
    export_dictionary,
    export_json,
    output_dir,
)
from c2_analyzer.dom.pipeline import extract_dom_features
from c2_analyzer.preprocessing import batch as part2
from c2_analyzer.preprocessing.loader import from_bytes
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.dom import DomResult


def _existing(json_path: Path, parsed_path: Path, sha256: str) -> DomResult | None:
    """The stored DomResult if it is still valid for this file and dictionary."""
    if not json_path.is_file():
        return None
    try:
        result = DomResult.model_validate_json(json_path.read_bytes())
    except ValueError:
        return None
    if (
        result.source_sha256 != sha256
        or result.dictionary_hash != dictionary_hash()
        or not parsed_path.is_file()
        or parsed_path.stat().st_mtime_ns > json_path.stat().st_mtime_ns  # Part 2 re-ran
    ):
        return None
    return result


def _row(task: dict, result: DomResult, status: str, part2_status: str) -> dict:
    return {
        "sample_id": task["sample_id"],
        "label": task["label"],
        "language": task["language"],
        "cluster_id": task["cluster_id"],
        "status": status,
        "part2": part2_status,
        "features": result.features,
        "processing_ms": result.processing_ms,
        "errors": list(result.errors),
        "evidence": len(result.evidence),
    }


def process_task(task: dict) -> dict:
    """Features for one sample (runs inside a worker process). Never raises."""
    base = {key: task[key] for key in ("sample_id", "label", "language", "cluster_id")}
    try:
        out_dir, parsed_dir = Path(task["out_dir"]), Path(task["parsed_dir"])
        json_path = out_dir / f"{task['sample_id']}.json"
        parsed_path = parsed_dir / f"{task['sample_id']}.json"
        if not task["force"]:
            result = _existing(json_path, parsed_path, task["sha256"])
            if result is not None:
                return _row(task, result, "skipped", "stored")

        raw = from_bytes(
            Path(task["file"]).read_bytes(),
            page_url=task["page_url"],
            sample_id=task["sample_id"],
            dataset_version=task["version"],
            label=task["label"],
        )
        page = part2._existing(parsed_path, task["sha256"])  # Part 2's own validity check
        part2_status = "stored"
        if page is None:
            page = preprocess(raw)
            part2.save_page(page, parsed_dir, task["sample_id"])
            part2_status = "processed"
        result = extract_dom_features(page, raw.html)
        export_json(result, json_path)
        return _row(task, result, "processed", part2_status)
    except Exception as error:  # noqa: BLE001 - one page must never stop the batch
        return {**base, "status": "failed", "error": f"{type(error).__name__}: {error}"}


def build_tasks(
    store: MetadataStore,
    version: str,
    label: str | None = None,
    limit: int | None = None,
    force: bool = False,
    out_dir: Path | None = None,
    parsed_dir: Path | None = None,
) -> list[dict]:
    """One task per manifest row (after the label/limit filters)."""
    csv_path, _ = manifest_paths(manifests_dir(store), version)
    if not csv_path.is_file():
        raise FileNotFoundError(f"no manifest for {version}: {csv_path} (freeze it first)")
    manifest = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    if label:
        manifest = manifest[manifest["label"] == label]
    if limit is not None:
        manifest = manifest.head(limit)
    urls = {}
    if store.csv_path.is_file():
        urls = {
            row["sample_id"]: row["final_url"] or row["source_url"]
            for row in store.df[["sample_id", "final_url", "source_url"]].to_dict("records")
        }
    directory = out_dir or output_dir(version)
    parsed_dir = parsed_dir or part2.output_dir(version)
    return [
        {
            "sample_id": row["sample_id"],
            "label": row["label"],
            "language": row["language"],
            "cluster_id": row["cluster_id"],
            "file": str(store.raw_dir / row["file_path"]),
            "page_url": urls.get(row["sample_id"]),
            "sha256": row["sha256"],
            "version": version,
            "out_dir": str(directory),
            "parsed_dir": str(parsed_dir),
            "force": force,
        }
        for row in manifest.to_dict("records")
    ]


def run_version(
    store: MetadataStore,
    version: str,
    label: str | None = None,
    limit: int | None = None,
    workers: int | None = None,
    force: bool = False,
    out_dir: Path | None = None,
    show_progress: bool = True,
    parsed_dir: Path | None = None,
) -> tuple[list[dict], float, list[dict], Path]:
    """Verify, extract, write CSV + dictionary -> (results, seconds, all rows, csv path).

    ``parsed_dir`` is where Part 2 JSON is read/saved (default: Part 2's own folder).
    """
    check = verify(store, version)
    if not check.ok:
        raise ValueError(
            f"dataset {version} failed verification ({len(check.missing)} missing, "
            f"{len(check.changed)} changed file(s)) - run "
            f"`python scripts/dataset_stats.py verify --version {version}` and fix it first"
        )
    load_dictionary()  # fail fast on a broken dictionary, before starting workers
    tasks = build_tasks(store, version, label, limit, force, out_dir, parsed_dir)
    started = time.perf_counter()
    config = load_yaml_config("config").get("dom_features", {})
    workers = workers or int(config.get("workers", 4))
    results = part2.run_tasks(
        tasks, workers, show_progress, worker=process_task, desc="DOM features"
    )
    seconds = time.perf_counter() - started
    directory = out_dir or output_dir(version)
    # The CSV always covers the WHOLE version (a --label/--limit run must not shrink it).
    rows = collect_rows(store, version, directory)
    csv_path = export_csv(rows, directory / CSV_NAME)
    export_dictionary(directory / DICTIONARY_NAME)
    return results, seconds, rows, csv_path


def collect_rows(store: MetadataStore, version: str, directory: Path) -> list[dict]:
    """Every manifest sample with a valid stored DomResult (current dictionary), in order."""
    csv_path, _ = manifest_paths(manifests_dir(store), version)
    manifest = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    rows = []
    for row in manifest.to_dict("records"):
        path = directory / f"{row['sample_id']}.json"
        if not path.is_file():
            continue
        try:
            result = DomResult.model_validate_json(path.read_bytes())
        except ValueError:
            continue
        if result.dictionary_hash != dictionary_hash() or result.source_sha256 != row["sha256"]:
            continue
        task = {key: row[key] for key in ("sample_id", "label", "language", "cluster_id")}
        rows.append(_row(task, result, "stored", "stored"))
    return rows
