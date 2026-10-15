"""Behavioral intent mapping of a whole frozen dataset version (Part 8 batch run).

Part 8: Behavioral intent mapping (sources -> sinks).

Same rules as the Part 3 / Part 7 batches, so all parts stay comparable:
- the manifest is verified first (files present, sha256 unchanged);
- inputs are the stored Part 2 ParsedPage and Part 7 JsAnalysisResult; a
  missing / stale one is produced (Part 2 / Part 7) and SAVED, so the earlier
  parts' outputs stay complete (Part 7's CSV is rebuilt when that happens);
- a sample is skipped when its stored result was made from the same file with
  the same Part 8 rules AND the same Part 7 rules, and is newer than both
  inputs; ``force`` redoes everything;
- parallel worker processes ("spawn") via Part 2's ``run_tasks``;
- one broken page is "failed" and never stops the batch.

Outputs:
    data/processed/behavior/<version>/<sample_id>.json        BehaviorResult (behavior_v1)
    data/processed/behavior/<version>/behavior_features.csv   ids + intent vector
    data/processed/behavior/<version>/behavior_feature_dictionary.json
The CSV is always rebuilt from ALL valid stored results of the version.
"""

from __future__ import annotations

import io
import time
from pathlib import Path

import pandas as pd

from c2_analyzer.behavior.pipeline import map_behavior
from c2_analyzer.behavior.rules import feature_names, load_behavior_rules, rules_hash
from c2_analyzer.config import load_yaml_config, resolve_path
from c2_analyzer.dataset.manifest import manifest_paths, manifests_dir, verify
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.js_analyzer import batch as part7
from c2_analyzer.js_analyzer.pipeline import analyze_js
from c2_analyzer.js_analyzer.rules import rules_hash as js_rules_hash
from c2_analyzer.preprocessing import batch as part2
from c2_analyzer.preprocessing.loader import from_bytes
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.behavior import BehaviorResult
from c2_analyzer.utils.io import atomic_write_text, write_json

ID_COLUMNS = ["sample_id", "label", "language", "cluster_id"]
CSV_NAME = "behavior_features.csv"
DICTIONARY_NAME = "behavior_feature_dictionary.json"


def _config() -> dict:
    return load_yaml_config("config").get("behavior", {})


def output_dir(version: str | None) -> Path:
    """data/processed/behavior/<version or "adhoc">/"""
    base = _config().get("output_dir", "data/processed/behavior")
    return resolve_path(Path(base)) / (version or "adhoc")


def reports_dir() -> Path:
    return resolve_path(Path(_config().get("reports_dir", "reports/behavior")))


def csv_columns() -> list[str]:
    return ID_COLUMNS + list(feature_names())


def export_json(result: BehaviorResult, path: Path) -> Path:
    atomic_write_text(result.model_dump_json(indent=1), path)
    return path


def export_csv(rows: list[dict], path: Path) -> Path:
    """The intent-vector table: ID columns, then features in behavior_features.yaml order."""
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
    """The vector definition used (+ the rules hash), for the baseline and the thesis."""
    rules = load_behavior_rules()
    write_json({"rules_hash": rules_hash(), **rules.raw["behavior_features"]}, path)
    return path


def stored_result(json_path: Path, sha256: str) -> BehaviorResult | None:
    """The stored result if it was made from this file with the current Part 7 + 8 rules."""
    if not json_path.is_file():
        return None
    try:
        result = BehaviorResult.model_validate_json(json_path.read_bytes())
    except ValueError:
        return None
    meta = result.meta
    if (
        meta.source_sha256 != sha256
        or meta.rules_hash != rules_hash()
        or meta.js_rules_hash != js_rules_hash()
    ):
        return None
    return result


def _row(task: dict, result: BehaviorResult, status: str, inputs: dict) -> dict:
    return {
        **{key: task[key] for key in ID_COLUMNS},
        "status": status,
        **inputs,
        "features": result.intent_vector,
        "risk_score": result.behavior_risk_score,
        "processing_ms": result.meta.processing_ms,
        "step_ms": result.meta.step_ms,
        "truncated": result.meta.truncated,
        "warnings": list(result.meta.warnings),
        "errors": list(result.errors),
        "summary": result.summary.model_dump(),
        "findings": [
            {
                "pattern": f.pattern_id,
                "variant": f.variant,
                "severity": f.severity,
                "severity_score": f.severity_score,
                "confidence": f.confidence,
                "message": f.message,
                "count": f.count,
            }
            for f in result.findings
        ],
        "flows": [
            {
                "source": flow.source_id,
                "sink": flow.sink_id,
                "confidence": flow.confidence,
                "external": flow.sink_is_external,
                "known_endpoint": flow.known_endpoint,
                "encoded": flow.encoded,
            }
            for flow in result.flows
        ],
    }


def _inputs(task: dict) -> tuple:
    """(ParsedPage, JsAnalysisResult, part2 status, part7 status) - produced and saved if needed."""
    parsed_dir, js_dir = Path(task["parsed_dir"]), Path(task["js_dir"])
    parsed_path = parsed_dir / f"{task['sample_id']}.json"
    js_path = js_dir / f"{task['sample_id']}.json"
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
    js_result = part7.stored_result(js_path, task["sha256"])  # Part 7's own validity check
    part7_status = "stored"
    if js_result is None or part2_status == "processed":
        js_result = analyze_js(page)
        part7.export_json(js_result, js_path)
        part7_status = "processed"
    return page, js_result, part2_status, part7_status


def process_task(task: dict) -> dict:
    """Map one sample (runs inside a worker process). Never raises."""
    base = {key: task[key] for key in ID_COLUMNS}
    try:
        json_path = Path(task["out_dir"]) / f"{task['sample_id']}.json"
        if not task["force"]:
            result = stored_result(json_path, task["sha256"])
            if result is not None:
                mtime = json_path.stat().st_mtime_ns
                inputs = [
                    Path(task["parsed_dir"]) / f"{task['sample_id']}.json",
                    Path(task["js_dir"]) / f"{task['sample_id']}.json",
                ]
                if all(p.is_file() and p.stat().st_mtime_ns <= mtime for p in inputs):
                    return _row(task, result, "skipped", {"part2": "stored", "part7": "stored"})
        page, js_result, part2_status, part7_status = _inputs(task)
        result = map_behavior(page, js_result)
        export_json(result, json_path)
        return _row(task, result, "processed", {"part2": part2_status, "part7": part7_status})
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
    js_dir: Path | None = None,
) -> list[dict]:
    """One task per manifest row (Part 7's task list + the Part 8 / Part 7 folders)."""
    tasks = part7.build_tasks(store, version, label, limit, force, out_dir, parsed_dir)
    directory = out_dir or output_dir(version)
    js_folder = js_dir or part7.output_dir(version)
    for task in tasks:
        task["out_dir"] = str(directory)
        task["js_dir"] = str(js_folder)
    return tasks


def collect_rows(store: MetadataStore, version: str, directory: Path) -> list[dict]:
    """Every manifest sample with a valid stored result (current rules), in manifest order."""
    csv_path, _ = manifest_paths(manifests_dir(store), version)
    manifest = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    rows = []
    for row in manifest.to_dict("records"):
        result = stored_result(directory / f"{row['sample_id']}.json", row["sha256"])
        if result is not None:
            task = {key: row[key] for key in ID_COLUMNS}
            rows.append(_row(task, result, "stored", {"part2": "stored", "part7": "stored"}))
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
    js_dir: Path | None = None,
) -> tuple[list[dict], float, list[dict], Path]:
    """Verify, map, write CSV + dictionary -> (results, seconds, all rows, csv path)."""
    check = verify(store, version)
    if not check.ok:
        raise ValueError(
            f"dataset {version} failed verification ({len(check.missing)} missing, "
            f"{len(check.changed)} changed file(s)) - run "
            f"`python scripts/dataset_stats.py verify --version {version}` and fix it first"
        )
    load_behavior_rules()  # fail fast on broken YAML, before starting workers
    tasks = build_tasks(store, version, label, limit, force, out_dir, parsed_dir, js_dir)
    started = time.perf_counter()
    workers = workers or int(_config().get("workers", 4))
    results = part2.run_tasks(
        tasks, workers, show_progress, worker=process_task, desc="Behavior mapping"
    )
    seconds = time.perf_counter() - started
    if any(r.get("part7") == "processed" for r in results):
        # Part 7 results were produced here: keep Part 7's CSV complete too
        js_folder = js_dir or part7.output_dir(version)
        part7.export_csv(part7.collect_rows(store, version, js_folder), js_folder / part7.CSV_NAME)
        part7.export_dictionary(js_folder / part7.DICTIONARY_NAME)
    directory = out_dir or output_dir(version)
    rows = collect_rows(store, version, directory)
    csv_path = export_csv(rows, directory / CSV_NAME)
    export_dictionary(directory / DICTIONARY_NAME)
    return results, seconds, rows, csv_path
