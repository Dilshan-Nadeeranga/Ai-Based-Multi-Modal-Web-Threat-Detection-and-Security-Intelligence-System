"""Corpus summary report + language-mismatch review list + one page as text (Part 5).

Part 5: Multilingual scam content analyzer.

Why: before Part 6 trains on this text we must know what it looks like per
class - which languages (the per-language XLM-R results depend on it), how much
text, which CTAs - and where Part 1's quick language hint (dataset metadata)
disagrees with Part 5's real language ID. The report is DESCRIPTIVE only.

Outputs (reports/content/):
    <version>_summary.json / .md        language distribution per label, metadata-vs-
                                        detected confusion table, segments per field
                                        per label, median chars, top 20 CTAs per label,
                                        pages with empty text, timing
    <version>_language_mismatch.csv     samples whose metadata language differs from
                                        the detected one - a REVIEW list; metadata.csv
                                        is never changed here
"""

from __future__ import annotations

import io
import statistics
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from c2_analyzer.config import get_labels, load_yaml_config
from c2_analyzer.content.batch import reports_dir
from c2_analyzer.content.extractor import FIELDS, rules_hash
from c2_analyzer.content.language import latin_backend
from c2_analyzer.dataset.page_view import terminal_safe
from c2_analyzer.schemas.content import PageText
from c2_analyzer.utils.io import atomic_write_text, write_json

TOP_CTAS = 20
MISMATCH_COLUMNS = [
    "sample_id", "label", "metadata_language", "detected_language", "confidence", "method",
    "si_ratio", "ta_ratio", "lang_attr", "title",
]  # fmt: skip


def _labels(present: set[str]) -> list[str]:
    """labels.yaml order, only the labels that occur."""
    return [label for label in get_labels() if label in present]


def detected_order() -> list[str]:
    """Part 5 language labels in configs/languages.yaml order (table columns)."""
    return list(load_yaml_config("languages")["language_id"]["labels"])


def _pct(part: int, whole: int) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


def _title(result: PageText) -> str:
    titles = result.by_field("title")
    return titles[0].text[:80] if titles else ""


def mismatches(stored: list[tuple[dict, PageText]]) -> list[dict]:
    """Rows where metadata.language != detected page language (si_latn / ta_latn / other
    never equal a metadata value, so those pages are always listed for review)."""
    rows = []
    for row, result in stored:
        detected = result.language.language
        if row["language"] == detected:
            continue
        rows.append(
            {
                "sample_id": row["sample_id"],
                "label": row["label"],
                "metadata_language": row["language"],
                "detected_language": detected,
                "confidence": result.language.confidence,
                "method": result.language.method,
                "si_ratio": result.language.script_ratios.get("si", 0.0),
                "ta_ratio": result.language.script_ratios.get("ta", 0.0),
                "lang_attr": result.language.lang_attr or "",
                "title": _title(result),
            }
        )
    return rows


def summarize(
    stored: list[tuple[dict, PageText]],
    results: list[dict],
    version: str,
    seconds: float,
    filters: dict | None = None,
) -> dict[str, Any]:
    """Everything the report shows, as one JSON-ready dict."""
    labels = _labels({row["label"] for row, _ in stored})
    detected_labels = detected_order()
    by_label: dict[str, list[PageText]] = {label: [] for label in labels}
    for row, result in stored:
        by_label[row["label"]].append(result)

    distribution = {
        label: {lang: 0 for lang in detected_labels} for label in labels
    }  # fmt: skip
    for row, result in stored:
        distribution[row["label"]][result.language.language] += 1
    distribution_pct = {
        label: {lang: _pct(n, len(by_label[label])) for lang, n in counts.items()}
        for label, counts in distribution.items()
    }

    metadata_values = sorted({row["language"] for row, _ in stored})
    confusion = {meta: {lang: 0 for lang in detected_labels} for meta in metadata_values}
    for row, result in stored:
        confusion[row["language"]][result.language.language] += 1

    segments_per_field = {
        label: {
            field: (
                round(statistics.mean(r.counts.get(field, 0) for r in pages), 2) if pages else 0.0
            )
            for field in FIELDS
        }
        for label, pages in by_label.items()
    }
    chars = {
        label: {
            "median_chars": statistics.median(r.chars for r in pages) if pages else 0,
            "median_page_text_chars": (
                statistics.median(r.page_text_chars for r in pages) if pages else 0
            ),
            "pct_page_text_truncated": _pct(sum(r.page_text_truncated for r in pages), len(pages)),
            "pct_has_cta": _pct(sum(r.has_cta for r in pages), len(pages)),
            "pct_has_form_labels": _pct(sum(r.has_form_labels for r in pages), len(pages)),
        }
        for label, pages in by_label.items()
    }

    top_ctas = {}
    for label, pages in by_label.items():
        seen: Counter[str] = Counter()
        shown: dict[str, str] = {}
        for result in pages:
            keys = set()
            for segment in result.by_field("cta"):
                key = " ".join(segment.text.casefold().split())
                keys.add(key)
                shown.setdefault(key, segment.text)
            seen.update(keys)  # pages, not occurrences
        top_ctas[label] = [
            {"text": shown[key], "pages": count} for key, count in seen.most_common(TOP_CTAS)
        ]

    empty = [
        {"sample_id": row["sample_id"], "label": row["label"]}
        for row, result in stored
        if result.empty
    ]
    methods = Counter(result.language.method for _, result in stored)
    failures = [r for r in results if r.get("status") == "failed"]
    times = [r.meta.processing_ms for _, r in stored]
    status = Counter(r.get("status") for r in results)
    mismatch_rows = mismatches(stored)
    return {
        "version": version,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "text_set_version": "text_v1",
        "rules_hash": rules_hash(),
        "language_backend": latin_backend().name,
        "filters": filters or {},
        "counts": {
            "run_total": len(results),
            "processed": status.get("processed", 0),
            "skipped_unchanged": status.get("skipped", 0),
            "failed": len(failures),
            "part2_processed_now": sum(1 for r in results if r.get("part2") == "processed"),
            "pages_in_index": len(stored),
            "empty_pages": len(empty),
            "language_mismatches": len(mismatch_rows),
            "with_errors": sum(1 for _, r in stored if r.meta.errors),
            "cta_from_parsed_page_only": sum(
                1 for _, r in stored if r.meta.cta_source == "parsed_page"
            ),
        },
        "timing": {
            "wall_seconds": round(seconds, 1),
            "median_ms": round(statistics.median(times), 1) if times else 0.0,
            "max_ms": round(max(times), 1) if times else 0.0,
        },
        "labels": labels,
        "detected_languages": detected_labels,
        "pages_per_label": {label: len(pages) for label, pages in by_label.items()},
        "language_distribution": distribution,
        "language_distribution_pct": distribution_pct,
        "page_language_methods": dict(methods.most_common()),
        "metadata_vs_detected": confusion,
        "segments_per_field_mean": segments_per_field,
        "text_size": chars,
        "top_ctas": top_ctas,
        "empty_pages": empty,
        "failures": [{"sample_id": r["sample_id"], "error": r.get("error")} for r in failures],
    }


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += [
        "| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in row) + " |"
        for row in rows
    ]
    return lines


def render_markdown(summary: dict) -> str:
    labels, langs, counts = summary["labels"], summary["detected_languages"], summary["counts"]
    lines = [
        f"# Content extraction & language ID (Part 5, Batch A) - {summary['version']}",
        "",
        f"Generated {summary['generated_at']} · rules `{summary['rules_hash'][:12]}` · "
        f"Latin-script backend **{summary['language_backend']}** · descriptive only (no "
        "classification).",
        "",
        f"Pages: {counts['pages_in_index']} (processed now {counts['processed']}, unchanged "
        f"{counts['skipped_unchanged']}, failed {counts['failed']}); empty text "
        f"{counts['empty_pages']}; metadata/detected language mismatches "
        f"{counts['language_mismatches']}; wall {summary['timing']['wall_seconds']} s, median "
        f"{summary['timing']['median_ms']} ms/page.",
        "",
        "## Page language per label (pages)",
        "",
    ]
    lines += _table(
        ["label", "pages"] + langs,
        [
            [label, summary["pages_per_label"][label]]
            + [summary["language_distribution"][label][lang] for lang in langs]
            for label in labels
        ],
    )
    lines += ["", "Page-language method: " + ", ".join(
        f"{method} {n}" for method, n in summary["page_language_methods"].items()
    ), ""]  # fmt: skip
    lines += [
        "## Metadata language (Part 1 hint, rows) vs detected (Part 5, columns)",
        "",
    ]
    confusion = summary["metadata_vs_detected"]
    lines += _table(
        ["metadata \\ detected"] + langs,
        [[meta] + [confusion[meta][lang] for lang in langs] for meta in confusion],
    )
    lines += [
        "",
        f"Review list: `{summary['version']}_language_mismatch.csv` (nothing is changed "
        "automatically; fix metadata in review if the detected language is right).",
        "",
        "## Segments per page (mean) per field",
        "",
    ]
    fields = list(FIELDS)
    lines += _table(
        ["label"] + fields,
        [
            [label] + [summary["segments_per_field_mean"][label][f] for f in fields]
            for label in labels
        ],
    )
    lines += ["", "## Text size", ""]
    lines += _table(
        ["label", "median chars", "median page_text chars", "% page_text cut", "% with CTA",
         "% with form labels"],
        [
            [label] + list(summary["text_size"][label].values())
            for label in labels
        ],
    )  # fmt: skip
    lines += ["", f"## Top {TOP_CTAS} CTA texts per label (pages, PII-masked)", ""]
    for label in labels:
        ctas = summary["top_ctas"][label]
        lines.append(f"**{label}**: " + (
            "; ".join(f"{c['text']} ({c['pages']})" for c in ctas) if ctas else "none"
        ))  # fmt: skip
        lines.append("")
    empty = summary["empty_pages"]
    lines += [f"## Pages with empty text ({len(empty)})", ""]
    lines += [", ".join(f"{p['sample_id']} ({p['label']})" for p in empty) or "None.", ""]
    if summary["failures"]:
        lines += ["## Failures", ""] + [
            f"- {f['sample_id']}: {f['error']}" for f in summary["failures"]
        ]
    lines += [
        "",
        "Known gap: Singlish / Tanglish (si_latn / ta_latn) are flagged by a small lexicon; "
        "XLM-R (Part 6) handles romanized Sinhala / Tamil poorly.",
        "",
        "Reproduce: `python scripts/build_text_corpus.py extract --version "
        + summary["version"]
        + "`",
        "",
    ]
    return "\n".join(lines)


def write_report(
    summary: dict, stored: list[tuple[dict, PageText]], out_dir: Path | None = None
) -> list[Path]:
    """Summary JSON + Markdown + the language-mismatch review CSV."""
    folder = out_dir or reports_dir()
    folder.mkdir(parents=True, exist_ok=True)
    version = summary["version"]
    json_path = folder / f"{version}_summary.json"
    md_path = folder / f"{version}_summary.md"
    csv_path = folder / f"{version}_language_mismatch.csv"
    write_json(summary, json_path)
    atomic_write_text(render_markdown(summary), md_path)
    buffer = io.StringIO()
    frame = pd.DataFrame.from_records(mismatches(stored), columns=MISMATCH_COLUMNS)
    frame.to_csv(buffer, index=False, lineterminator="\n")
    atomic_write_text(buffer.getvalue(), csv_path)
    return [json_path, md_path, csv_path]


# ---- one page as text -------------------------------------------------------------------


def describe_result(result: PageText, label: str | None = None) -> str:
    """Segments grouped by field with language tags, then page_text (terminal-safe)."""
    language = result.language
    lines = [
        f"{result.meta.sample_id or 'page'}" + (f" (label: {label})" if label else ""),
        f"Page language: {language.language} (confidence {language.confidence:.2f}, method "
        f"{language.method}, backend {language.backend}); shares "
        + ", ".join(f"{k} {v:.2f}" for k, v in language.shares.items())
        + "; scripts "
        + ", ".join(f"{k} {v:.2f}" for k, v in language.script_ratios.items())
        + (f"; <html lang={language.lang_attr!r}>" if language.lang_attr else ""),
        f"{len(result.segments)} segment(s), {result.chars} visible chars, CTA source "
        f"{result.meta.cta_source}; dropped "
        + (", ".join(f"{k} {v}" for k, v in result.meta.dropped.items()) or "nothing"),
    ]
    if result.meta.truncated:
        lines.append("Truncated: " + ", ".join(result.meta.truncation_reasons))
    for problem in result.meta.errors + result.meta.warnings:
        lines.append(f"Note: {problem}")
    for field in FIELDS:
        segments = result.by_field(field)
        if not segments:
            continue
        lines += ["", f"== {field} ({len(segments)})"]
        for segment in segments:
            extra = f" h{segment.level}" if segment.level else ""
            extra += f" x{segment.count}" if segment.count > 1 else ""
            tag = f"[{segment.language} {segment.lang_confidence:.2f} {segment.lang_method}]"
            lines.append(f"  {segment.segment_id}{extra} {tag} {terminal_safe(segment.text)}")
    lines += [
        "",
        f"== page_text ({result.page_text_chars} chars"
        + (", truncated" if result.page_text_truncated else "")
        + ")",
        terminal_safe(result.page_text),
    ]
    return "\n".join(lines)
