"""Extract the text of a whole frozen dataset version (Part 5 batch run).

Part 5: Multilingual scam content analyzer.

Same rules as the Part 3 / 7 / 8 batches, so all parts stay comparable:
- the manifest is verified first (files present, sha256 unchanged);
- input is the stored Part 2 ParsedPage; a missing / stale one is produced by
  Part 2 and SAVED. The raw HTML is also read, because CTA / alert facts come
  from it (``content/cta.py``) - the same HTML the API path uses;
- a sample is skipped when its stored PageText was made from the same file with
  the same rules (``rules_hash``: content.yaml + languages.yaml + extractor
  version + language backend) and is newer than its ParsedPage; ``force`` redoes;
- parallel worker processes ("spawn") via Part 2's ``run_tasks``;
- one broken page is "failed" and never stops the batch.

Outputs:
    data/processed/text/<version>/<sample_id>.json   PageText (text_v1)
    data/processed/text/<version>/text_index.csv     one row per page (see INDEX_COLUMNS)
The index is always rebuilt from ALL valid stored results of the version.
"""

from __future__ import annotations

import io
import time
from pathlib import Path

import pandas as pd

from c2_analyzer.config import load_yaml_config, resolve_path
from c2_analyzer.content.extractor import content_rules, extract_content, rules_hash
from c2_analyzer.dataset.manifest import manifest_paths, manifests_dir, verify
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.preprocessing import batch as part2
from c2_analyzer.preprocessing.loader import from_bytes
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.content import PageText
from c2_analyzer.utils.io import atomic_write_text

ID_COLUMNS = ["sample_id", "label", "language", "cluster_id"]
INDEX_NAME = "text_index.csv"
INDEX_COLUMNS = [
    "sample_id", "label", "cluster_id", "page_language", "lang_confidence", "n_segments",
    "chars", "has_cta", "has_form_labels", "si_ratio", "ta_ratio",
]  # fmt: skip


def _config() -> dict:
    return load_yaml_config("config").get("content", {})


def output_dir(version: str | None) -> Path:
    """data/processed/text/<version or "adhoc">/"""
    base = _config().get("output_dir", "data/processed/text")
    return resolve_path(Path(base)) / (version or "adhoc")


def reports_dir() -> Path:
    return resolve_path(Path(_config().get("reports_dir", "reports/content")))


def export_json(result: PageText, path: Path) -> Path:
    atomic_write_text(result.model_dump_json(indent=1), path)
    return path


def stored_result(json_path: Path, sha256: str) -> PageText | None:
    """The stored PageText if it was made from this file with the current rules."""
    if not json_path.is_file():
        return None
    try:
        result = PageText.model_validate_json(json_path.read_bytes())
    except ValueError:
        return None
    if result.meta.source_sha256 != sha256 or result.meta.rules_hash != rules_hash():
        return None
    return result


def index_row(task: dict, result: PageText) -> dict:
    """One text_index.csv row."""
    return {
        "sample_id": task["sample_id"],
        "label": task["label"],
        "cluster_id": task["cluster_id"],
        "page_language": result.language.language,
        "lang_confidence": result.language.confidence,
        "n_segments": len(result.segments),
        "chars": result.chars,
        "has_cta": int(result.has_cta),
        "has_form_labels": int(result.has_form_labels),
        "si_ratio": result.language.script_ratios.get("si", 0.0),
        "ta_ratio": result.language.script_ratios.get("ta", 0.0),
    }


def _row(task: dict, result: PageText, status: str, part2_status: str) -> dict:
    return {
        **{key: task[key] for key in ID_COLUMNS},
        "status": status,
        "part2": part2_status,
        "index": index_row(task, result),
        "processing_ms": result.meta.processing_ms,
        "errors": list(result.meta.errors),
    }


def process_task(task: dict) -> dict:
    """Text for one sample (runs inside a worker process). Never raises."""
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
        result = extract_content(page, raw.html)
        export_json(result, json_path)
        return _row(task, result, "processed", part2_status)
    except Exception as error:  # noqa: BLE001 - one page must never stop the batch
        return {**base, "status": "failed", "error": f"{type(error).__name__}: {error}"}


def _manifest(store: MetadataStore, version: str) -> pd.DataFrame:
    csv_path, _ = manifest_paths(manifests_dir(store), version)
    if not csv_path.is_file():
        raise FileNotFoundError(f"no manifest for {version}: {csv_path} (freeze it first)")
    return pd.read_csv(csv_path, dtype=str, keep_default_na=False)


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
    manifest = _manifest(store, version)
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


def collect_results(
    store: MetadataStore, version: str, directory: Path
) -> list[tuple[dict, PageText]]:
    """(manifest row, PageText) for every sample with a valid stored result, manifest order."""
    found = []
    for row in _manifest(store, version).to_dict("records"):
        result = stored_result(directory / f"{row['sample_id']}.json", row["sha256"])
        if result is not None:
            found.append((row, result))
    return found


def export_index(results: list[tuple[dict, PageText]], path: Path) -> Path:
    records = [index_row(row, result) for row, result in results]
    buffer = io.StringIO()
    frame = pd.DataFrame.from_records(records, columns=INDEX_COLUMNS)
    frame.to_csv(buffer, index=False, lineterminator="\n")
    atomic_write_text(buffer.getvalue(), path)
    return path


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
) -> tuple[list[dict], float, list[tuple[dict, PageText]], Path]:
    """Verify, extract, write the index -> (task results, seconds, all stored, index path)."""
    check = verify(store, version)
    if not check.ok:
        raise ValueError(
            f"dataset {version} failed verification ({len(check.missing)} missing, "
            f"{len(check.changed)} changed file(s)) - run "
            f"`python scripts/dataset_stats.py verify --version {version}` and fix it first"
        )
    content_rules()  # fail fast on a broken YAML, before starting workers
    tasks = build_tasks(store, version, label, limit, force, out_dir, parsed_dir)
    started = time.perf_counter()
    workers = workers or int(_config().get("workers", 4))
    results = part2.run_tasks(
        tasks, workers, show_progress, worker=process_task, desc="Text extraction"
    )
    seconds = time.perf_counter() - started
    directory = out_dir or output_dir(version)
    stored = collect_results(store, version, directory)
    index_path = export_index(stored, directory / INDEX_NAME)
    return results, seconds, stored, index_path
