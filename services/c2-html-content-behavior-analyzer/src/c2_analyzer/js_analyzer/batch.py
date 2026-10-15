"""Analyze the JavaScript of a whole frozen dataset version (Part 7 batch run).

Part 7: Static JavaScript intent analyzer.

Same rules as the Part 3 batch, so all parts stay comparable:
- the manifest is verified first (files present, sha256 unchanged);
- input is the stored Part 2 ParsedPage; a missing / stale one is produced by
  Part 2 and SAVED, so Part 2's outputs stay complete;
- a sample is skipped when its stored result was made from the same file with
  the same rules (``rules_hash``: both YAML files + analyzer + parser
  version) and is newer than its ParsedPage; ``force`` redoes everything;
- parallel worker processes ("spawn") via Part 2's ``run_tasks``;
- one broken page is "failed" and never stops the batch.

Outputs:
    data/processed/js/<version>/<sample_id>.json   JsAnalysisResult (js_v1)
    data/processed/js/<version>/js_features.csv    sample_id, label, language, cluster_id + features
    data/processed/js/<version>/js_feature_dictionary.json
The CSV is always rebuilt from ALL valid stored results of the version.
"""

from __future__ import annotations

import io
import time
from pathlib import Path

import pandas as pd

from c2_analyzer.config import load_yaml_config, resolve_path
from c2_analyzer.dataset.manifest import manifest_paths, manifests_dir, verify
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.js_analyzer.pipeline import analyze_js
from c2_analyzer.js_analyzer.rules import feature_names, load_rules, rules_hash
from c2_analyzer.preprocessing import batch as part2
from c2_analyzer.preprocessing.loader import from_bytes
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.js import JsAnalysisResult
from c2_analyzer.utils.io import atomic_write_text, write_json

ID_COLUMNS = ["sample_id", "label", "language", "cluster_id"]
CSV_NAME = "js_features.csv"
DICTIONARY_NAME = "js_feature_dictionary.json"


def _config() -> dict:
    return load_yaml_config("config").get("js_analyzer", {})


def output_dir(version: str | None) -> Path:
    """data/processed/js/<version or "adhoc">/"""
    base = _config().get("output_dir", "data/processed/js")
    return resolve_path(Path(base)) / (version or "adhoc")


def reports_dir() -> Path:
    return resolve_path(Path(_config().get("reports_dir", "reports/js_analysis")))


def csv_columns() -> list[str]:
    return ID_COLUMNS + list(feature_names())


def export_json(result: JsAnalysisResult, path: Path) -> Path:
    atomic_write_text(result.model_dump_json(indent=1), path)
    return path


def export_csv(rows: list[dict], path: Path) -> Path:
    """The feature table: ID columns, then features in js_features.yaml order."""
    records = [
        {**{column: row.get(column, "") for column in ID_COLUMNS}, **row["features"]}
        for row in rows
    ]
    buffer = io.StringIO()
    frame = pd.DataFrame.from_records(records, columns=csv_columns())
    frame.to_csv(buffer, index=False, lineterminator="\n")
    atomic_write_text(buffer.getvalue(), path)
    return path


def export_dictionary(path: Path) -> Path:
    """The feature dictionary used (+ the rules hash), for later parts and the thesis."""
    rules = load_rules()
    write_json({"rules_hash": rules_hash(), **rules.raw["js_features"]}, path)
    return path


def stored_result(json_path: Path, sha256: str) -> JsAnalysisResult | None:
    """The stored result if it was made from this file with the current rules."""
    if not json_path.is_file():
        return None
    try:
        result = JsAnalysisResult.model_validate_json(json_path.read_bytes())
    except ValueError:
        return None
    if result.meta.source_sha256 != sha256 or result.meta.rules_hash != rules_hash():
        return None
    return result


def _row(task: dict, result: JsAnalysisResult, status: str, part2_status: str) -> dict:
    return {
        "sample_id": task["sample_id"],
        "label": task["label"],
        "language": task["language"],
        "cluster_id": task["cluster_id"],
        "status": status,
        "part2": part2_status,
        "features": result.features,
        "processing_ms": result.meta.processing_ms,
        "step_ms": result.meta.step_ms,
        "errors": list(result.meta.errors),
        "summary": result.summary.model_dump(),
        "scripts": [
            {
                "source": s.source,
                "parser": s.parser,
                "library": s.library,
                "chars": s.analyzed_chars,
                "truncated": s.truncated,
                "timed_out": s.timed_out,
            }
            for s in result.scripts
        ],
        "counts": [c.model_dump() for c in result.counts],
    }


def process_task(task: dict) -> dict:
    """Analyze one sample (runs inside a worker process). Never raises."""
    base = {key: task[key] for key in ID_COLUMNS}
    try:
        out_dir, parsed_dir = Path(task["out_dir"]), Path(task["parsed_dir"])
        json_path = out_dir / f"{task['sample_id']}.json"
        parsed_path = parsed_dir / f"{task['sample_id']}.json"
        if not task["force"]:
            result = stored_result(json_path, task["sha256"])
            fresh = (
                result is not None
                and parsed_path.is_file()
                and parsed_path.stat().st_mtime_ns <= json_path.stat().st_mtime_ns
            )
            if fresh:
                return _row(task, result, "skipped", "stored")
        page = part2._existing(parsed_path, task["sha256"])  # Part 2's own validity check
        part2_status = "stored"
        if page is None:
            raw = from_bytes(
                Path(task["file"]).read_bytes(),
                page_url=task["page_url"],
                sample_id=task["sample_id"],
                dataset_version=task["version"],
                label=task["label"],
            )
            page = preprocess(raw)
            part2.save_page(page, parsed_dir, task["sample_id"])
            part2_status = "processed"
        result = analyze_js(page)
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
    """One task per manifest row (after the label / limit filters)."""
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
            **{key: row[key] for key in ID_COLUMNS},
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


def collect_rows(store: MetadataStore, version: str, directory: Path) -> list[dict]:
    """Every manifest sample with a valid stored result (current rules), in manifest order."""
    csv_path, _ = manifest_paths(manifests_dir(store), version)
    manifest = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    rows = []
    for row in manifest.to_dict("records"):
        result = stored_result(directory / f"{row['sample_id']}.json", row["sha256"])
        if result is not None:
            task = {key: row[key] for key in ID_COLUMNS}
            rows.append(_row(task, result, "stored", "stored"))
    return rows


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
    """Verify, analyze, write CSV + dictionary -> (results, seconds, all rows, csv path)."""
    check = verify(store, version)
    if not check.ok:
        raise ValueError(
            f"dataset {version} failed verification ({len(check.missing)} missing, "
            f"{len(check.changed)} changed file(s)) - run "
            f"`python scripts/dataset_stats.py verify --version {version}` and fix it first"
        )
    load_rules()  # fail fast on broken YAML, before starting workers
    tasks = build_tasks(store, version, label, limit, force, out_dir, parsed_dir)
    started = time.perf_counter()
    workers = workers or int(_config().get("workers", 4))
    results = part2.run_tasks(
        tasks, workers, show_progress, worker=process_task, desc="JS analysis"
    )
    seconds = time.perf_counter() - started
    directory = out_dir or output_dir(version)
    rows = collect_rows(store, version, directory)
    csv_path = export_csv(rows, directory / CSV_NAME)
    export_dictionary(directory / DICTIONARY_NAME)
    return results, seconds, rows, csv_path
