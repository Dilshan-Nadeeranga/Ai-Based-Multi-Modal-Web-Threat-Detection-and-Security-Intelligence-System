"""Collection runner: fetch candidates, register the pages, track progress.

Part 1: Multilingual dataset preparation (Batch B).

Why: this is the glue between the two stages. For each candidate it fetches
the page, decides the language (hint from the feed, else the script-based
guess), registers the page through the same ``register_file`` used for
hand-saved pages (so all Batch A validation and duplicate checks apply), and
records the outcome in candidates.csv. Both CSVs are saved after every URL,
so stopping with Ctrl+C never loses work.
"""

from __future__ import annotations

import tempfile
from collections import Counter
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from c2_analyzer.config import get_labels, get_languages, load_yaml_config
from c2_analyzer.dataset.candidates import Candidate, CandidateStore
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.fetcher import FetchResult
from c2_analyzer.dataset.metadata import DuplicateSampleError, MetadataStore
from c2_analyzer.utils.script_detect import detect_html_language
from c2_analyzer.utils.url import extract_domain

OUTCOMES = ("saved", "skipped", "failed", "duplicate")


def build_notes(candidate: Candidate, result: FetchResult) -> str | None:
    """Candidate notes, plus a review flag when a scam URL redirected to another site.

    A dead phishing link often redirects to the real brand (e.g. paypal.com);
    that page is NOT phishing, so it is flagged for manual verification.
    """
    parts = [candidate.notes] if candidate.notes else []
    original, final = extract_domain(candidate.url), extract_domain(result.final_url or "")
    if candidate.suggested_label != "benign" and final and final != original:
        parts.append(f"redirected to {final} - check the label")
    return "; ".join(parts) or None


def process_candidate(
    candidate: Candidate,
    fetcher,
    metadata: MetadataStore,
    candidates: CandidateStore,
) -> tuple[str, list[str]]:
    """Fetch and register one candidate. Returns (outcome, warnings)."""
    result = fetcher.fetch(candidate.url)
    if result.outcome != "ok":
        candidates.mark(candidate.url, result.outcome, error=result.reason)
        return result.outcome, []

    language = candidate.language_hint
    if language == "unknown":
        language = detect_html_language(result.html)

    # register_file copies a file, so write the decoded page (UTF-8) to a temp file.
    with tempfile.TemporaryDirectory() as temp_dir:
        page = Path(temp_dir) / "page.html"
        page.write_text(result.html, encoding="utf-8")
        try:
            record, warnings = register_file(
                metadata,
                page,
                label=candidate.suggested_label,
                language=language,
                source=candidate.source,
                source_url=candidate.url,
                notes=build_notes(candidate, result),
                fetch_mode=fetcher.mode,
                final_url=result.final_url,
                http_status=result.http_status,
                content_type=result.content_type,
            )
        except DuplicateSampleError as error:
            candidates.mark(
                candidate.url, "duplicate", error=str(error), sample_id=error.existing_sample_id
            )
            return "duplicate", []
        except ValueError as error:  # e.g. invalid metadata value
            candidates.mark(candidate.url, "failed", error=f"invalid metadata: {error}")
            return "failed", []

    candidates.mark(candidate.url, "fetched", sample_id=record.sample_id)
    return "saved", warnings


def collect(
    to_fetch: list[Candidate],
    fetcher,
    metadata: MetadataStore,
    candidates: CandidateStore,
    show_progress: bool = True,
) -> Counter:
    """Process candidates one by one with a progress bar. Returns outcome counts.

    Ctrl+C stops after saving; the remaining candidates stay "pending".
    """
    counts: Counter = Counter({outcome: 0 for outcome in OUTCOMES})
    bar = tqdm(to_fetch, unit="url", disable=not show_progress)
    try:
        for candidate in bar:
            outcome, warnings = process_candidate(candidate, fetcher, metadata, candidates)
            counts[outcome] += 1
            for warning in warnings:
                tqdm.write(f"Warning ({candidate.url}): {warning}")
            # Save after every URL so an interruption never loses finished work.
            metadata.save()
            candidates.save()
            bar.set_postfix(counts)
    except KeyboardInterrupt:
        tqdm.write("Interrupted - progress so far is saved.")
    finally:
        bar.close()
    return counts


def progress_table(metadata_df: pd.DataFrame, targets: dict | None = None) -> pd.DataFrame:
    """Registered samples per label x language, compared with configs/collection_targets.yaml."""
    if targets is None:
        targets = load_yaml_config("collection_targets")
    labels, languages = list(get_labels()), list(get_languages())

    table = pd.crosstab(metadata_df["label"], metadata_df["language"])
    table = table.reindex(index=labels, columns=languages, fill_value=0)
    table["total"] = table.sum(axis=1)
    table["target"] = [targets["overall"].get(label, 0) for label in labels]

    todo = []
    for label in labels:
        missing = []
        overall_gap = table.loc[label, "target"] - table.loc[label, "total"]
        if overall_gap > 0:
            missing.append(f"{overall_gap} more")
        for language, per_label in targets.get("per_language", {}).items():
            gap = per_label.get(label, 0) - table.loc[label, language]
            if gap > 0:
                missing.append(f"{gap} more {language}")
        todo.append(", ".join(missing) or "done")
    table["still needed"] = todo
    table.index.name = "label"
    return table
