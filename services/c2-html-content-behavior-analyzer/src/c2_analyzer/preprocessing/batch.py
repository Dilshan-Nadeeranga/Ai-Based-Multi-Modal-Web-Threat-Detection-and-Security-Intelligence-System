"""Preprocess a whole frozen dataset version and save the outputs (Task 12).

Part 2: HTML preprocessing pipeline.

Why: training (Parts 3-6) must use exactly the pages of one frozen dataset
version (Part 1 manifest), processed once and stored, so experiments are
reproducible and fast. For every sample of the manifest this writes

    data/processed/parsed_html/<version>/<sample_id>.json   ParsedPage
    data/processed/parsed_html/<version>/<sample_id>.txt    visible_text only (Part 5)

Rules:
- the manifest is checked first (every file present, sha256 unchanged);
  if that fails nothing is processed - the outputs would not match the version;
- a sample is skipped when its JSON already exists with the same source
  sha256, schema version and domain method (use force=True to redo everything);
- pages are processed in parallel worker processes ("spawn", which is what
  Windows uses anyway). Workers receive and return plain dicts;
- one broken page is recorded as "failed" and never stops the batch;
- files are written atomically, so Ctrl+C never leaves a half-written JSON.
"""

from __future__ import annotations

import multiprocessing
import time
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from c2_analyzer.config import resolve_path
from c2_analyzer.dataset.manifest import manifest_paths, manifests_dir, verify
from c2_analyzer.dataset.metadata import MetadataStore
from c2_analyzer.preprocessing.loader import from_bytes
from c2_analyzer.preprocessing.pipeline import preprocess, to_json
from c2_analyzer.preprocessing.settings import PreprocessSettings, default_settings
from c2_analyzer.schemas.parsed_page import SCHEMA_VERSION, ParsedPage
from c2_analyzer.utils.io import atomic_write_text
from c2_analyzer.utils.url import domain_method

ADHOC = "adhoc"  # output folder for pages that are not part of a dataset version


def output_dir(version: str | None, settings: PreprocessSettings | None = None) -> Path:
    """data/processed/parsed_html/<version or "adhoc">/"""
    settings = settings or default_settings()
    return resolve_path(Path(settings.output_dir)) / (version or ADHOC)


def page_metrics(page: ParsedPage) -> dict:
    """The few numbers the batch summary needs (descriptive only)."""
    inputs = page.all_inputs
    return {
        "processing_ms": page.meta.processing_ms,
        "parser_used": page.meta.parser_used,
        "truncated": page.meta.truncated,
        "errors": list(page.meta.errors),
        "visible_chars": len(page.visible_text),
        "has_form": bool(page.forms),
        "has_password": any(field.type == "password" for field in inputs),
        "has_inline_script": bool(page.scripts_inline),
        "has_external_script": bool(page.scripts_external),
        "has_iframe": any(item.tag in ("iframe", "frame") for item in page.embedded),
        "has_meta_refresh": page.meta_refresh is not None,
    }


def save_page(page: ParsedPage, directory: Path, name: str) -> Path:
    """Write <name>.json (ParsedPage) and <name>.txt (visible text). Returns the JSON path."""
    json_path = directory / f"{name}.json"
    atomic_write_text(to_json(page), json_path)
    atomic_write_text(page.visible_text, directory / f"{name}.txt")
    return json_path


def _existing(json_path: Path, sha256: str) -> ParsedPage | None:
    """The saved page if it was made from the same file with the current schema."""
    if not json_path.is_file():
        return None
    try:
        page = ParsedPage.model_validate_json(json_path.read_bytes())
    except ValueError:
        return None  # damaged or from an incompatible schema: process again
    if (
        page.meta.source_sha256 != sha256
        or page.meta.schema_version != SCHEMA_VERSION
        or page.meta.domain_method != domain_method()  # e.g. tldextract installed since
    ):
        return None
    return page


def process_task(task: dict) -> dict:
    """Process one sample (runs inside a worker process). Never raises."""
    result = {"sample_id": task["sample_id"], "label": task["label"]}
    try:
        directory = Path(task["out_dir"])
        if not task["force"]:
            page = _existing(directory / f"{task['sample_id']}.json", task["sha256"])
            if page is not None:
                return {**result, "status": "skipped", **page_metrics(page)}
        raw = from_bytes(
            Path(task["file"]).read_bytes(),
            page_url=task["page_url"],
            sample_id=task["sample_id"],
            dataset_version=task["version"],
            label=task["label"],
        )
        page = preprocess(raw)
        save_page(page, directory, task["sample_id"])
        return {**result, "status": "processed", **page_metrics(page)}
    except Exception as error:  # noqa: BLE001 - one page must never stop the batch
        return {**result, "status": "failed", "error": f"{type(error).__name__}: {error}"}


def build_tasks(
    store: MetadataStore,
    version: str,
    label: str | None = None,
    limit: int | None = None,
    force: bool = False,
    out_dir: Path | None = None,
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

    urls = {
        row["sample_id"]: row["final_url"] or row["source_url"]
        for row in store.df[["sample_id", "final_url", "source_url"]].to_dict("records")
    }
    directory = out_dir or output_dir(version)
    return [
        {
            "sample_id": row["sample_id"],
            "label": row["label"],
            "file": str(store.raw_dir / row["file_path"]),
            "page_url": urls.get(row["sample_id"]),
            "sha256": row["sha256"],
            "version": version,
            "out_dir": str(directory),
            "force": force,
        }
        for row in manifest.to_dict("records")
    ]


def run_tasks(
    tasks: list[dict],
    workers: int,
    show_progress: bool = True,
    worker: Callable[[dict], dict] | None = None,
    desc: str = "Preprocessing",
) -> list[dict]:
    """Run the tasks, in parallel when workers > 1. Results come back in task order.

    ``worker`` (default ``process_task``) must be a module-level function that
    never raises - Part 3 reuses this runner with its own worker.
    """
    worker = worker or process_task
    bar = tqdm(total=len(tasks), desc=desc, unit="page", disable=not show_progress)
    results: dict[str, dict] = {}
    try:
        if workers <= 1 or len(tasks) <= 1:
            for task in tasks:
                results[task["sample_id"]] = worker(task)
                bar.update()
        else:
            context = multiprocessing.get_context("spawn")  # same on Windows, Linux and macOS
            with ProcessPoolExecutor(max_workers=workers, mp_context=context) as pool:
                futures = {pool.submit(worker, task): task for task in tasks}
                for future in as_completed(futures):
                    task = futures[future]
                    try:
                        results[task["sample_id"]] = future.result()
                    except Exception as error:  # noqa: BLE001 - e.g. a worker process died
                        results[task["sample_id"]] = {
                            "sample_id": task["sample_id"],
                            "label": task["label"],
                            "status": "failed",
                            "error": f"worker crashed: {type(error).__name__}: {error}",
                        }
                    bar.update()
    finally:
        bar.close()
    return [results[task["sample_id"]] for task in tasks if task["sample_id"] in results]


def run_version(
    store: MetadataStore,
    version: str,
    label: str | None = None,
    limit: int | None = None,
    workers: int | None = None,
    force: bool = False,
    out_dir: Path | None = None,
    show_progress: bool = True,
) -> tuple[list[dict], float]:
    """Verify the manifest, then process its samples. Returns (results, wall seconds)."""
    check = verify(store, version)
    if not check.ok:
        raise ValueError(
            f"dataset {version} failed verification ({len(check.missing)} missing, "
            f"{len(check.changed)} changed file(s)) - run "
            f"`python scripts/dataset_stats.py verify --version {version}` and fix it first"
        )
    tasks = build_tasks(store, version, label, limit, force, out_dir)
    started = time.perf_counter()
    results = run_tasks(tasks, workers or default_settings().workers, show_progress)
    return results, time.perf_counter() - started
