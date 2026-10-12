"""Collection runner: fetch candidates, register the pages, track progress.

Part 1: Multilingual dataset preparation (Batch B).

Why: this is the glue between the two stages. For each candidate it fetches
the page, decides the language (hint from the feed, else the script-based
guess), registers the page through the same ``register_file`` used for
hand-saved pages (so all Batch A validation and duplicate checks apply), and
records the outcome in candidates.csv. Both CSVs are saved after every URL,
so stopping with Ctrl+C never loses work.

Robustness: one bad candidate never stops a run. Any error while handling a
page (e.g. Windows Defender quarantining the file we just wrote) marks that
candidate "failed" with the reason, and the run continues. Downloaded pages
are written to data/tmp/ (inside the project, never the system Temp folder),
so an antivirus exclusion for data/ covers every file the collector writes.
"""

from __future__ import annotations

import errno
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from c2_analyzer.config import get_labels, get_languages, load_yaml_config
from c2_analyzer.dataset.candidates import Candidate, CandidateStore
from c2_analyzer.dataset.collector import register_file
from c2_analyzer.dataset.fetcher import FetchResult
from c2_analyzer.dataset.metadata import DuplicateSampleError, MetadataStore
from c2_analyzer.utils.io import remove_quietly
from c2_analyzer.utils.script_detect import detect_html_language
from c2_analyzer.utils.url import extract_domain

OUTCOMES = ("saved", "skipped", "failed", "duplicate")

# Windows error codes for "the file contains a virus" / "...was deleted".
ANTIVIRUS_WINERRORS = {225, 226}
ANTIVIRUS_PREFIX = "blocked_by_antivirus"


@dataclass
class CandidateOutcome:
    """What happened to one candidate: outcome (see OUTCOMES), error text, warnings."""

    outcome: str
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class CollectSummary:
    """Result of a fetch run: outcome counts and why pages were skipped/failed."""

    counts: Counter
    reasons: Counter


def temp_dir_for(metadata: MetadataStore) -> Path:
    """data/tmp/ - next to data/raw/, so the same antivirus exclusion covers both."""
    return metadata.raw_dir.parent / "tmp"


def is_antivirus_block(error: OSError) -> bool:
    """True if a file we just wrote vanished or cannot be opened (typical antivirus action).

    Errno 22 ("Invalid argument") is how Windows reports a file that Defender
    is quarantining; WinError 225/226 say it directly.
    """
    return (
        isinstance(error, FileNotFoundError)
        or error.errno == errno.EINVAL
        or getattr(error, "winerror", None) in ANTIVIRUS_WINERRORS
    )


# (text in the error message, short reason code) - first match wins.
REASON_PATTERNS = [
    (ANTIVIRUS_PREFIX, ANTIVIRUS_PREFIX),
    ("pruned_by_filter", "pruned_by_filter"),
    ("not HTML", "non_html_content"),
    ("larger than", "too_large"),
    ("too large", "too_large"),
    ("timeout", "timeout"),
    ("redirects", "too_many_redirects"),
    ("blocked", "blocked_host"),
    ("getaddrinfo failed", "dns_error"),
    ("Name or service not known", "dns_error"),
    ("nodename nor servname", "dns_error"),
    ("10054", "connection_reset"),
    ("Connection reset", "connection_reset"),
    ("10061", "connection_refused"),
    ("Connection refused", "connection_refused"),
    ("SSL", "tls_error"),
    ("CERTIFICATE", "tls_error"),
    ("invalid metadata", "invalid_metadata"),
    ("browser error", "browser_error"),
]


def reason_code(error: str | None) -> str:
    """Turn a stored last_error message into a short code for counting.

    E.g. "HTTP 404" -> "http_404", "timeout after 15s" -> "timeout".
    It only reads the text, so it also works on rows saved by older runs.
    """
    if not error:
        return "unknown"
    if match := re.match(r"HTTP (\d{3})", error):
        return f"http_{match[1]}"
    for pattern, code in REASON_PATTERNS:
        if pattern in error:
            return code
    # Otherwise use the exception type stored by the fetcher ("ReadError: ...").
    if match := re.match(r"(\w+(?:Error|Exception)):", error):
        return match[1].lower()
    return "other"


def reason_breakdown(df: pd.DataFrame) -> Counter:
    """Count reason codes over candidates.csv rows (use it on failed/skipped rows)."""
    return Counter(reason_code(error) for error in df["last_error"])


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


def _fetch_and_register(
    candidate: Candidate,
    fetcher,
    metadata: MetadataStore,
    candidates: CandidateStore,
) -> CandidateOutcome:
    """The normal path for one candidate (unexpected errors are handled by the caller)."""
    result = fetcher.fetch(candidate.url)
    if result.outcome != "ok":
        candidates.mark(candidate.url, result.outcome, error=result.reason)
        return CandidateOutcome(result.outcome, result.reason)

    language = candidate.language_hint
    if language == "unknown":
        language = detect_html_language(result.html)

    # register_file copies a file, so write the decoded page (UTF-8) to data/tmp/
    # first. Never the system Temp folder: it is not covered by the antivirus
    # exclusion, so phishing pages there get quarantined while we read them.
    temp_dir = temp_dir_for(metadata)
    temp_dir.mkdir(parents=True, exist_ok=True)
    page = temp_dir / f"{uuid.uuid4().hex}.html"
    try:
        page.write_text(result.html, encoding="utf-8")
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
        return CandidateOutcome("duplicate", str(error))
    except ValueError as error:  # e.g. invalid metadata value
        reason = f"invalid metadata: {error}"
        candidates.mark(candidate.url, "failed", error=reason)
        return CandidateOutcome("failed", reason)
    finally:
        remove_quietly(page)  # if it is locked now, 'collect.py repair' removes it later

    candidates.mark(candidate.url, "fetched", sample_id=record.sample_id)
    return CandidateOutcome("saved", warnings=warnings)


def process_candidate(
    candidate: Candidate,
    fetcher,
    metadata: MetadataStore,
    candidates: CandidateStore,
) -> CandidateOutcome:
    """Fetch and register one candidate. Never raises because of a problem with this page.

    Any error is stored as the candidate's last_error and it is marked "failed"
    (so it can be retried). KeyboardInterrupt is not an ``Exception``, so
    Ctrl+C still stops the run.
    """
    try:
        return _fetch_and_register(candidate, fetcher, metadata, candidates)
    except OSError as error:
        if is_antivirus_block(error):
            reason = f"{ANTIVIRUS_PREFIX}: {error}"
        else:
            reason = f"{type(error).__name__}: {error}"
    except Exception as error:  # noqa: BLE001 - one bad page must not stop the whole run
        reason = f"{type(error).__name__}: {error}"
    candidates.mark(candidate.url, "failed", error=reason)
    return CandidateOutcome("failed", reason)


def collect(
    to_fetch: list[Candidate],
    fetcher,
    metadata: MetadataStore,
    candidates: CandidateStore,
    show_progress: bool = True,
) -> CollectSummary:
    """Process candidates one by one with a progress bar.

    Returns the outcome counts and a count of skip/fail reasons.
    Ctrl+C stops after saving; the remaining candidates stay "pending".
    """
    counts: Counter = Counter({outcome: 0 for outcome in OUTCOMES})
    reasons: Counter = Counter()
    bar = tqdm(to_fetch, unit="url", disable=not show_progress)
    try:
        for candidate in bar:
            result = process_candidate(candidate, fetcher, metadata, candidates)
            counts[result.outcome] += 1
            if result.outcome in ("skipped", "failed"):
                reasons[reason_code(result.error)] += 1
            for warning in result.warnings:
                tqdm.write(f"Warning ({candidate.url}): {warning}")
            # Save after every URL so an interruption never loses finished work.
            # Metadata first: if the second save fails, 'collect.py repair' can
            # link the candidate to the sample that was saved.
            metadata.save()
            candidates.save()
            bar.set_postfix(counts)
    except KeyboardInterrupt:
        tqdm.write("Interrupted - progress so far is saved.")
    finally:
        bar.close()
    return CollectSummary(counts, reasons)


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
