"""Human review of high-risk live results -> rows for the Part 1 manual feed.

Part 9: Batch B-2 - automatic ThreatRadar ingestion.

Why (viva): a live verdict is a MODEL OUTPUT, not a label. If C2 added its own
Malicious verdicts to the training set, the next model would learn its predecessor's
mistakes as truth (confirmation bias, a feedback loop). So high-risk results wait in
``review_queue``; a person confirms (or corrects / rejects) each one in
``scripts/review_live.py``; only CONFIRMED items are exported, as rows of the Part 1
manual feed (``url,label,language_hint,source,notes``). They then enter the dataset
through the normal Part 1 pipeline (``collect.py import --feed manual`` -> fetch ->
quality checks -> label review -> dedup -> a NEW frozen version), never directly.

Sources follow the Part 1 ThreatRadar importer (configs/threatradar_rules.yaml):
Telegram / Reddit -> ``social_media_report``, everything else -> ``other``; the notes say
"ThreatRadar live" + the analysis id, so every row can be traced back to its scan.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from pathlib import Path

from c2_analyzer.config import get_labels
from c2_analyzer.dataset.candidates import Candidate, allowed_language_hints
from c2_analyzer.store.repository import ResultsStore
from c2_analyzer.utils.url import normalize_url

MANUAL_FEED_COLUMNS = ("url", "label", "language_hint", "source", "notes")
# Part 5 page languages that are not metadata language hints
LANGUAGE_TO_HINT = {"si_latn": "si", "ta_latn": "ta"}


def language_hint(page_language: str | None) -> str:
    """Part 5 page language -> a Part 1 ``language_hint`` (unknown if not allowed)."""
    value = LANGUAGE_TO_HINT.get(page_language or "", page_language or "unknown")
    return value if value in allowed_language_hints() else "unknown"


def dataset_source(job_source: str, source_ref: dict) -> str:
    """Part 1 metadata source for a live item (same mapping as the ThreatRadar importer)."""
    if source_ref.get("channel") or source_ref.get("message_id") is not None:
        return "social_media_report"  # Telegram
    if source_ref.get("subreddit") or source_ref.get("post_id"):
        return "social_media_report"  # Reddit
    return "other"  # domain filter, API, user checks


def _context(source_ref: dict) -> str:
    parts = []
    if source_ref.get("channel") or source_ref.get("message_id") is not None:
        parts.append(
            f"channel @{source_ref.get('channel') or '?'} "
            f"message_id={source_ref.get('message_id', '?')}"
        )
    if source_ref.get("subreddit") or source_ref.get("post_id"):
        parts.append(
            f"r/{source_ref.get('subreddit') or '?'} " f"post_id={source_ref.get('post_id') or '?'}"
        )
    if source_ref.get("reasons"):
        parts.append(f"reasons={','.join(source_ref['reasons'])}")
    return "; ".join(parts)


def export_row(item: dict) -> dict[str, str]:
    """One confirmed review item -> one manual-feed row (validated like Part 1 does)."""
    ref = item.get("source_ref") or {}
    context = _context(ref)
    notes = (
        f"ThreatRadar live: analysis_id={item['analysis_id']}; job={item['job_id']}; "
        f"C2 verdict {item.get('verdict')} {item.get('threat_class') or ''} "
        f"risk {item.get('risk_score')}; confirmed by {item.get('decided_by')}"
        + (f"; {context}" if context else "")
    )
    row = {
        "url": item["url"],
        "label": item["decided_label"],
        "language_hint": language_hint(item.get("page_language")),
        "source": dataset_source(item.get("source", ""), ref),
        "notes": notes,
    }
    # Exactly the checks parse_manual -> Candidate applies; a bad row fails here, not later.
    Candidate(
        url=row["url"],
        suggested_label=row["label"],
        language_hint=row["language_hint"],
        source=row["source"],
        notes=row["notes"],
    )
    return row


@dataclass
class ExportReport:
    written: int
    already_in_file: int
    path: Path


def export_confirmed(store: ResultsStore, path: Path, include_demo: bool = False) -> ExportReport:
    """Append confirmed, not yet exported items to a manual-feed CSV (created if missing).

    URLs already in the file (normalized like Part 1) are not written twice. Written and
    skipped items are both marked exported, so the next run only sees new decisions.
    """
    items = [
        item
        for item in store.reviews("confirmed")
        if item["exported_at"] is None and (include_demo or not item["demo"])
    ]
    path = Path(path)
    existing: set[str] = set()
    if path.is_file():
        with path.open(encoding="utf-8-sig", newline="") as handle:
            lines = [line for line in handle if not line.lstrip().startswith("#")]
        for row in csv.DictReader(io.StringIO("".join(lines))):
            if row.get("url"):
                existing.add(normalize_url(row["url"]))
    rows, skipped = [], 0
    for item in items:
        key = normalize_url(item["url"])
        if key in existing:
            skipped += 1
            continue
        existing.add(key)
        rows.append(export_row(item))
    if rows:
        path.parent.mkdir(parents=True, exist_ok=True)
        new_file = not path.is_file() or path.stat().st_size == 0
        needs_newline = not new_file and not path.read_bytes().endswith(b"\n")
        with path.open("a", encoding="utf-8", newline="") as handle:
            if needs_newline:
                handle.write("\n")
            writer = csv.DictWriter(handle, fieldnames=MANUAL_FEED_COLUMNS, lineterminator="\n")
            if new_file:
                writer.writeheader()
            writer.writerows(rows)
    store.mark_exported([item["job_id"] for item in items])
    return ExportReport(written=len(rows), already_in_file=skipped, path=path)


def check_label(label: str) -> str:
    if label not in get_labels():
        raise ValueError(f"unknown label {label!r}; allowed: {', '.join(get_labels())}")
    return label


def describe_item(item: dict) -> str:
    """A review item as plain, terminal-safe text (URLs defanged, never clickable)."""
    from c2_analyzer.dataset.page_view import terminal_safe
    from c2_analyzer.ingest.service import display_url
    from c2_analyzer.utils.defang import defang_host, defang_text

    ref = item.get("source_ref") or {}
    lines = [
        f"job {item['job_id']}  [{item.get('source')}]{'  DEMO' if item.get('demo') else ''}",
        f"  url:      {display_url(item.get('url'))}",
        f"  domain:   {defang_host(item.get('final_url_domain')) or '-'}",
        f"  C2 says:  {item.get('verdict')} {item.get('threat_class') or ''} "
        f"risk {item.get('risk_score')}  (language {item.get('page_language') or '?'})",
        f"  queued:   {item.get('reason')}",
    ]
    context = _context(ref)
    if context:
        lines.append(f"  seen:     {context}")
    for finding in item.get("top_findings") or []:
        lines.append(f"  - [{finding.get('severity')}] {defang_text(finding.get('title'))}")
    return terminal_safe("\n".join(lines))
