"""Summaries of preprocessing: the batch report and a readable one-page view.

Part 2: HTML preprocessing pipeline.

Why: after a batch run I need to see at a glance whether it worked (how many
pages processed / failed, parser fallbacks, truncated pages, timing) and
what the pages look like per label - for the progress report. The numbers
are descriptive only (e.g. "% of pages with a password input"); they do not
classify anything.

    reports/preprocessing/<version>_summary.json
    reports/preprocessing/<version>_summary.md

``describe_page`` prints one ParsedPage as plain text for
``preprocess_html.py one`` (page strings pass through terminal_safe first).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from c2_analyzer.config import get_labels, resolve_path
from c2_analyzer.dataset.page_view import terminal_safe
from c2_analyzer.dataset.statistics import percent, quantile
from c2_analyzer.dataset.stats_report import md_table
from c2_analyzer.preprocessing.settings import default_settings
from c2_analyzer.schemas.parsed_page import SCHEMA_VERSION, ParsedPage
from c2_analyzer.utils.io import atomic_write_text, write_json

FLAGS = {
    "pct_with_forms": "has_form",
    "pct_with_password_input": "has_password",
    "pct_with_inline_scripts": "has_inline_script",
    "pct_with_external_scripts": "has_external_script",
    "pct_with_iframes": "has_iframe",
    "pct_with_meta_refresh": "has_meta_refresh",
}


def summarize(results: list[dict], version: str, wall_seconds: float, filters: dict) -> dict:
    """Counts, timing and the per-label table for one batch run."""
    ok = [r for r in results if r["status"] in ("processed", "skipped")]
    times = [r["processing_ms"] for r in ok]
    per_label = {}
    for label in get_labels():
        rows = [r for r in ok if r["label"] == label]
        if not rows:
            continue
        per_label[label] = {
            "pages": len(rows),
            "median_visible_chars": quantile([r["visible_chars"] for r in rows], 0.5),
            **{name: percent(sum(r[key] for r in rows), len(rows)) for name, key in FLAGS.items()},
        }
    return {
        "version": version,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "schema_version": SCHEMA_VERSION,
        "filters": filters,
        "counts": {
            "total": len(results),
            "processed": sum(r["status"] == "processed" for r in results),
            "skipped_unchanged": sum(r["status"] == "skipped" for r in results),
            "failed": sum(r["status"] == "failed" for r in results),
        },
        "failures": [
            {"sample_id": r["sample_id"], "error": r["error"]}
            for r in results
            if r["status"] == "failed"
        ],
        "pages_with_step_errors": [
            {"sample_id": r["sample_id"], "errors": r["errors"]} for r in ok if r["errors"]
        ],
        "parser_fallbacks": [r["sample_id"] for r in ok if r["parser_used"] != "lxml"],
        "truncated": [r["sample_id"] for r in ok if r["truncated"]],
        "timing": {
            "wall_seconds": round(wall_seconds, 1),
            "avg_processing_ms": round(sum(times) / len(times), 1) if times else None,
            "p95_processing_ms": quantile(times, 0.95),
            "max_processing_ms": max(times) if times else None,
        },
        "per_label": per_label,
    }


def render_markdown(summary: dict) -> str:
    counts, timing = summary["counts"], summary["timing"]
    out = [f"# Preprocessing summary - dataset {summary['version']}", ""]
    out.append(
        f"- Generated: {summary['generated_at']} (ParsedPage schema {summary['schema_version']})"
    )
    filters = {k: v for k, v in summary["filters"].items() if v not in (None, False)}
    if filters:
        out.append(f"- Filters: {filters}")
    out += [
        f"- Pages: {counts['total']} (processed {counts['processed']}, unchanged/skipped "
        f"{counts['skipped_unchanged']}, failed {counts['failed']})",
        f"- Pages with a step error (partial result): {len(summary['pages_with_step_errors'])}",
        f"- Parser fallbacks (not lxml): {len(summary['parser_fallbacks'])}",
        f"- Truncated pages: {len(summary['truncated'])}",
        f"- Time per page: avg {timing['avg_processing_ms']} ms, "
        f"p95 {timing['p95_processing_ms']} ms, "
        f"max {timing['max_processing_ms']} ms (wall time {timing['wall_seconds']} s)",
        "",
        "## Per label (descriptive)",
        "",
    ]
    headers = [
        "label",
        "pages",
        "median visible chars",
        "% forms",
        "% password input",
        "% inline scripts",
        "% external scripts",
        "% iframes",
        "% meta refresh",
    ]
    rows = [
        [label, row["pages"], row["median_visible_chars"], *(row[name] for name in FLAGS)]
        for label, row in summary["per_label"].items()
    ]
    out.append(md_table(headers, rows))
    if summary["failures"]:
        out += ["", "## Failures", ""]
        out.append(
            md_table(
                ["sample_id", "error"], [[f["sample_id"], f["error"]] for f in summary["failures"]]
            )
        )
    return "\n".join(out) + "\n"


def write_summary(summary: dict, reports_dir: Path | None = None) -> tuple[Path, Path]:
    """Write <version>_summary.json and .md; returns both paths."""
    directory = reports_dir or resolve_path(Path(default_settings().reports_dir))
    json_path = directory / f"{summary['version']}_summary.json"
    md_path = directory / f"{summary['version']}_summary.md"
    write_json(summary, json_path)
    atomic_write_text(render_markdown(summary), md_path)
    return json_path, md_path


# ---- one page as text --------------------------------------------------------------------------


def _short(text: str | None, limit: int) -> str:
    text = terminal_safe(text or "").replace("\n", " / ")
    return text if len(text) <= limit else text[:limit] + "..."


def describe_page(page: ParsedPage, label: str | None = None, max_forms: int = 3) -> str:
    """A readable text summary of one ParsedPage (never renders the page)."""
    meta = page.meta
    inputs_in_forms = sum(len(form.inputs) for form in page.forms)
    external_links = sum(link.is_external for link in page.links)
    lines = [
        f"{meta.sample_id or '(ad-hoc page)'}"
        + (f"  ({label})" if label else "")
        + (f"  dataset {meta.dataset_version}" if meta.dataset_version else ""),
        f"URL:        {_short(meta.page_url, 150) or '-'}",
        f"Base URL:   {_short(meta.base_url, 150) or '-'}",
        f"Title:      {_short(page.title, 150) or '-'}",
        f"lang={page.lang_attr or '-'}  charset={page.charset_declared or '-'}  "
        f"parser={meta.parser_used}  size={meta.html_size_bytes / 1024:.1f} KB  "
        f"time={meta.processing_ms:.0f} ms  truncated={meta.truncated}",
        f"Counts:     {len(page.headings)} headings, {len(page.paragraphs)} paragraphs, "
        f"{len(page.forms)} forms ({inputs_in_forms} inputs), "
        f"{len(page.inputs_outside_forms)} inputs outside forms, "
        f"{len(page.links)} links ({external_links} external), "
        f"{len(page.scripts_inline)} inline / {len(page.scripts_external)} external scripts, "
        f"{len(page.event_handlers)} event handlers, {len(page.javascript_urls)} javascript: URLs, "
        f"{len(page.embedded)} embedded, {page.comments.count} comments, "
        f"{page.dom.element_count} elements (depth {page.dom.max_depth})",
        f"Visible:    {_short(page.visible_text, 300)}",
    ]
    if page.hidden_text:
        lines.append(f"Hidden:     {_short(page.hidden_text, 200)}")
    if page.meta_refresh:
        lines.append(
            "Refresh:    "
            + _short(page.meta_refresh.redirect_url or page.meta_refresh.content, 150)
        )

    for form in page.forms[:max_forms]:
        where = "external" if form.is_external_action else "same site"
        lines.append(
            f"Form [{form.index}]: {form.method} "
            f"{_short(form.action_abs, 120) or '(no URL)'}  ({where})"
        )
        for field in form.inputs:
            details = [f"name={_short(field.name, 40)}"] if field.name else []
            if field.label_text:
                details.append(f'label="{_short(field.label_text, 40)}"')
            if field.required:
                details.append("required")
            if field.hidden and field.type != "hidden":
                details.append("hidden")
            if field.value_present:
                details.append(f"value={_short(field.value_masked, 40)}")
            lines.append(f"    {field.type:<10} {' '.join(details)}")
        for button in form.buttons:
            lines.append(f"    [button {button.type}] {_short(button.text or button.value, 40)}")
    if len(page.forms) > max_forms:
        lines.append(f"... {len(page.forms) - max_forms} more form(s)")

    if page.scripts_inline:
        heads = sum(script.position == "head" for script in page.scripts_inline)
        chars = sum(script.chars for script in page.scripts_inline)
        lines.append(
            f"Inline JS:  {len(page.scripts_inline)} script(s), {chars:,} chars "
            f"(head {heads}, body {len(page.scripts_inline) - heads})"
        )
    for script in page.scripts_external[:5]:
        flags = [
            name
            for name, on in (
                ("async", script.is_async),
                ("defer", script.defer),
                ("external", script.is_external),
            )
            if on
        ]
        lines.append(f"External JS: {_short(script.src_abs, 120)}  {' '.join(flags)}")
    if len(page.scripts_external) > 5:
        lines.append(f"... {len(page.scripts_external) - 5} more external script(s)")
    lines.append(f"Errors:     {'; '.join(meta.errors) if meta.errors else 'none'}")
    return "\n".join(lines)
