"""Reports for Part 7: the batch summary, one page as text, the feature dictionary.

Part 7: Static JavaScript intent analyzer.

Descriptive only (Part 8 decides intent): which share of the pages of each
label uses each API category (page-own code), median counts, how often
tree-sitter could parse the scripts, how much code is library code, the
most-used APIs and how long it took.

    reports/js_analysis/<version>_summary.json
    reports/js_analysis/<version>_summary.md
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from c2_analyzer.config import get_labels
from c2_analyzer.js_analyzer.ast_parser import parser_version
from c2_analyzer.js_analyzer.batch import reports_dir
from c2_analyzer.js_analyzer.rules import load_rules, rules_hash
from c2_analyzer.schemas.js import JsAnalysisResult
from c2_analyzer.utils.io import atomic_write_text, write_json


def _pct(part: float, whole: float) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


def _percentile(values: list[float], share: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(int(share * len(ordered)), len(ordered) - 1)], 2)


def summarize(
    rows: list[dict], results: list[dict], version: str, seconds: float, filters: dict
) -> dict:
    """Everything the report shows, from the CSV rows (all stored results) and this run."""
    rules = load_rules()
    statuses = Counter(r["status"] for r in results)
    labels = [label for label in get_labels() if any(r["label"] == label for r in rows)]
    categories = list(rules.categories)
    count_features = [spec.name for spec in rules.features if spec.count is not None]

    # parsing + library share (over every analysed script of the version)
    scripts = [s for r in rows for s in r["scripts"] if s["parser"] != "skipped"]
    inline = [s for s in scripts if s["source"] == "inline"]
    library_scripts = [s for s in inline if s["library"]]
    libraries = Counter(s["library"] for s in library_scripts)
    parsing = {
        "scripts_analyzed": len(scripts),
        "tree_sitter_ok": sum(s["parser"] == "tree-sitter" for s in scripts),
        "lexical_fallback": sum(s["parser"] == "lexical" for s in scripts),
        "parse_success_rate": _pct(
            sum(s["parser"] == "tree-sitter" for s in scripts), len(scripts)
        ),
        "timed_out": sum(s["timed_out"] for s in scripts),
        "truncated": sum(s["truncated"] for s in scripts),
        "by_source": {
            source: {
                "scripts": sum(s["source"] == source for s in scripts),
                "lexical": sum(s["source"] == source and s["parser"] == "lexical" for s in scripts),
            }
            for source in ("inline", "event_handler", "javascript_url")
        },
    }
    library = {
        "inline_scripts": len(inline),
        "library_scripts": len(library_scripts),
        "library_script_share": _pct(len(library_scripts), len(inline)),
        "library_char_share": _pct(
            sum(s["chars"] for s in library_scripts), sum(s["chars"] for s in inline)
        ),
        "pages_with_library": sum(any(s["library"] for s in r["scripts"]) for r in rows),
        "libraries": dict(libraries.most_common()),
        "detections_in_library": sum(
            r["summary"]["detections_total"] - r["summary"]["detections_page_own"] for r in rows
        ),
        "detections_page_own": sum(r["summary"]["detections_page_own"] for r in rows),
    }

    per_label: dict[str, Any] = {}
    for label in labels:
        group = [r for r in rows if r["label"] == label]
        per_label[label] = {
            "pages": len(group),
            "pages_with_js": sum(bool(r["scripts"]) for r in group),
            "category_pct": {
                category: _pct(
                    sum(r["summary"]["categories_page_own"].get(category, 0) > 0 for r in group),
                    len(group),
                )
                for category in categories
            },
            "median": {
                name: statistics.median([r["features"][name] for r in group])
                for name in count_features
            },
            "nonzero_pct": {
                name: _pct(sum(r["features"][name] > 0 for r in group), len(group))
                for name in count_features
            },
            "flags_pct": {
                flag: _pct(sum(r["summary"]["flags"].get(flag, False) for r in group), len(group))
                for flag in (group[0]["summary"]["flags"] if group else {})
            },
        }

    api_total: Counter = Counter()
    api_pages: Counter = Counter()
    api_library: Counter = Counter()
    for r in rows:
        for count in r["counts"]:
            api_total[count["api"]] += count["page_own"]
            api_library[count["api"]] += count["library"]
            if count["page_own"]:
                api_pages[count["api"]] += 1
    top_apis = [
        {
            "api": api,
            "category": rules.category(api),
            "page_own": total,
            "pages": api_pages[api],
            "pages_pct": _pct(api_pages[api], len(rows)),
            "library": api_library[api],
        }
        for api, total in api_total.most_common()
        if total
    ]

    # Per-page times come from the stored results (each keeps the time it took
    # when it was made), so a re-run that skips everything still reports them.
    timed = [r["processing_ms"] for r in rows]
    steps = defaultdict(float)
    for r in rows:
        for key, value in (r.get("step_ms") or {}).items():
            steps[key] += value
    return {
        "dataset_version": version,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "feature_set_version": rules.feature_set_version,
        "feature_count": len(rules.features),
        "rules_hash": rules_hash(),
        "parser": parser_version(),
        "filters": filters,
        "counts": {
            "run_total": len(results),
            "processed": statuses.get("processed", 0),
            "skipped_unchanged": statuses.get("skipped", 0),
            "failed": statuses.get("failed", 0),
            "part2_processed_now": sum(r.get("part2") == "processed" for r in results),
            "rows_in_csv": len(rows),
            "pages_with_errors": sum(bool(r["errors"]) for r in rows),
        },
        "failures": [
            {"sample_id": r["sample_id"], "error": r.get("error", "")}
            for r in results
            if r["status"] == "failed"
        ],
        "timing": {
            "pages_timed": len(timed),
            "avg_ms": round(statistics.mean(timed), 1) if timed else 0.0,
            "median_ms": round(statistics.median(timed), 1) if timed else 0.0,
            "p95_ms": _percentile(timed, 0.95),
            "max_ms": round(max(timed), 1) if timed else 0.0,
            "wall_seconds": round(seconds, 1),
            "step_ms_total": {key: round(value, 1) for key, value in steps.items()},
        },
        "parsing": parsing,
        "library": library,
        "external_scripts": {
            "total": sum(r["features"]["external_script_count"] for r in rows),
            "third_party": sum(r["features"]["third_party_script_count"] for r in rows),
            "known_cdn": sum(r["features"]["known_cdn_script_count"] for r in rows),
            "suspicious_host": sum(
                r["features"]["external_script_suspicious_host_count"] for r in rows
            ),
        },
        "labels": labels,
        "categories": categories,
        "per_label": per_label,
        "top_apis": top_apis,
    }


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def _num(value: float) -> str:
    return f"{value:g}" if isinstance(value, float) else str(value)


def render_markdown(summary: dict) -> str:
    counts, timing, parsing, library = (
        summary["counts"],
        summary["timing"],
        summary["parsing"],
        summary["library"],
    )
    labels = summary["labels"]
    out = [
        f"# Static JavaScript analysis - dataset {summary['dataset_version']}",
        "",
        "Part 7 (static AST analysis, nothing executed, nothing downloaded). Descriptive only: "
        "Part 8 decides intent. Counts are **page-own** code (library code excluded).",
        "",
        f"- Created: {summary['created_at']}",
        f"- Parser: {summary['parser']}",
        f"- Feature set: {summary['feature_set_version']} ({summary['feature_count']} features), "
        f"rules hash `{summary['rules_hash'][:12]}`",
        f"- Pages: {counts['rows_in_csv']} in CSV - this run processed {counts['processed']}, "
        f"unchanged {counts['skipped_unchanged']}, failed {counts['failed']}",
        f"- Time per page: avg {timing['avg_ms']} ms, median {timing['median_ms']} ms, "
        f"p95 {timing['p95_ms']} ms, max {timing['max_ms']} ms; wall {timing['wall_seconds']} s",
        "",
        "## Parsing",
        "",
        f"- Scripts analysed: {parsing['scripts_analyzed']} - "
        f"tree-sitter {parsing['tree_sitter_ok']}, "
        f"lexical fallback {parsing['lexical_fallback']} "
        f"(**parse success rate {parsing['parse_success_rate']} %**)",
        f"- Timed out: {parsing['timed_out']}, truncated at the size limit: {parsing['truncated']}",
        "",
        _md_table(
            ["source", "scripts", "lexical fallback"],
            [[k, v["scripts"], v["lexical"]] for k, v in parsing["by_source"].items()],
        ),
        "",
        "## Library code",
        "",
        f"- Inline scripts recognised as a library: {library['library_scripts']} of "
        f"{library['inline_scripts']} ({library['library_script_share']} % of scripts, "
        f"{library['library_char_share']} % of inline characters); pages with a library: "
        f"{library['pages_with_library']}",
        f"- Detections in library code (kept, not counted): {library['detections_in_library']}; "
        f"page-own: {library['detections_page_own']}",
        "",
        _md_table(["library", "inline scripts"], [[k, v] for k, v in library["libraries"].items()]),
        "",
        f"External scripts (reference only, content not analysed): "
        f"{summary['external_scripts']['total']} - "
        f"third-party {summary['external_scripts']['third_party']}, "
        f"known CDN {summary['external_scripts']['known_cdn']}, suspicious host "
        f"{summary['external_scripts']['suspicious_host']}",
        "",
        "## % of pages using each API category (page-own code)",
        "",
        _md_table(
            [
                "category",
                *[f"{label} (n={summary['per_label'][label]['pages']})" for label in labels],
            ],
            [
                [
                    category,
                    *[
                        _num(summary["per_label"][label]["category_pct"][category])
                        for label in labels
                    ],
                ]
                for category in summary["categories"]
            ],
        ),
        "",
        "## Count features: median (and % of pages with > 0)",
        "",
    ]
    features = list(next(iter(summary["per_label"].values()))["median"]) if labels else []
    out.append(
        _md_table(
            ["feature", *labels],
            [
                [
                    feature,
                    *[
                        f"{_num(summary['per_label'][label]['median'][feature])} "
                        f"({_num(summary['per_label'][label]['nonzero_pct'][feature])} %)"
                        for label in labels
                    ],
                ]
                for feature in features
            ],
        )
    )
    out += [
        "",
        "## Most used APIs (page-own)",
        "",
        _md_table(
            ["api", "category", "uses", "pages", "% pages", "in libraries"],
            [
                [a["api"], a["category"], a["page_own"], a["pages"], a["pages_pct"], a["library"]]
                for a in summary["top_apis"][:30]
            ],
        ),
        "",
    ]
    if summary["failures"]:
        out += ["## Failures", ""] + [
            f"- {f['sample_id']}: {f['error']}" for f in summary["failures"]
        ]
    return "\n".join(out) + "\n"


def write_report(summary: dict, out_dir: Path | None = None) -> list[Path]:
    directory = out_dir or reports_dir()
    json_path = directory / f"{summary['dataset_version']}_summary.json"
    md_path = directory / f"{summary['dataset_version']}_summary.md"
    write_json(summary, json_path)
    atomic_write_text(render_markdown(summary), md_path)
    return [json_path, md_path]


# ---- one page as text (CLI ``one``) -----------------------------------------------------


def describe_result(result: JsAnalysisResult, label: str | None = None) -> str:
    """Detections grouped by category, with line numbers and snippets (plain text)."""
    meta, summary = result.meta, result.summary
    lines = [
        f"Sample: {meta.sample_id or '(file)'}" + (f"   label: {label}" if label else ""),
        f"Page URL: {meta.page_url or '(unknown)'}",
        f"Parser: {meta.parser}   time: {meta.processing_ms} ms   rules {meta.rules_hash[:12]}",
        f"Scripts: {summary.scripts_analyzed} analysed "
        f"({summary.scripts_lexical} lexical fallback, "
        f"{summary.library_scripts} library: {', '.join(summary.libraries) or '-'}); "
        f"external <script src>: {len(result.external_scripts)}",
        f"Detections: {summary.detections_total} ({summary.detections_page_own} page-own)",
    ]
    for line in meta.errors:
        lines.append(f"ERROR: {line}")
    for line in meta.warnings:
        lines.append(f"Note: {line}")
    flags = [name for name, value in summary.flags.items() if value]
    lines.append("Flags (page-own): " + (", ".join(flags) if flags else "none"))

    lines.append("\nScripts:")
    for script in result.scripts:
        obf = script.obfuscation
        extra = []
        if script.library:
            extra.append(f"library={script.library}")
        if script.parser != "tree-sitter":
            extra.append(f"parser={script.parser}")
        if script.truncated:
            extra.append("truncated")
        if obf is not None:
            extra.append(f"entropy={obf.entropy}")
            if obf.minified:
                extra.append("minified")
            if obf.signatures:
                extra.append("obfuscation=" + "+".join(obf.signatures))
        if script.detections:
            extra.append(f"{script.detections} detection(s)")
        lines.append(
            f"  [{script.index}] {script.origin}: {script.analyzed_chars:,} chars  "
            + "  ".join(extra)
        )

    if result.external_scripts:
        lines.append("\nExternal scripts (not downloaded):")
        for ext in result.external_scripts:
            tags = ["third-party" if ext.is_external else "same site"]
            if ext.known_cdn:
                tags.append("known CDN")
            if ext.library:
                tags.append(ext.library)
            tags += ext.flags
            if not ext.has_integrity and ext.is_external:
                tags.append("no integrity")
            lines.append(f"  [{ext.index}] {ext.src}  ({', '.join(tags)})")

    by_category: dict[str, list] = defaultdict(list)
    for detection in result.detections:
        by_category[detection.category].append(detection)
    lines.append("\nDetections by category:")
    if not by_category:
        lines.append("  none")
    for category in load_rules().categories:
        found = by_category.get(category)
        if not found:
            continue
        own = sum(not d.in_library for d in found)
        lines.append(f"\n  {category} ({own} page-own, {len(found) - own} library)")
        for d in found:
            facts = [d.access]
            if d.confidence == "low":
                facts.append("LOW confidence")
            if d.in_library:
                facts.append("library")
            if d.selector:
                facts.append(f"selector {d.selector}")
            if d.event_type:
                facts.append(f"event {d.event_type}")
            if d.assigned_to:
                facts.append(f"-> {d.assigned_to}")
            if d.args and d.args.url:
                where = "EXTERNAL" if d.args.url_is_external else "same site"
                facts.append(f"url {d.args.url} ({where})")
            if d.args and d.args.http_method:
                facts.append(d.args.http_method)
            if d.args and d.args.identifiers_used:
                facts.append("uses " + ", ".join(d.args.identifiers_used[:6]))
            if d.enclosing_function:
                facts.append(f"in {d.enclosing_function}")
            script = result.scripts[d.script_index]
            lines.append(
                f"    {d.api:<28} script {d.script_index} ({script.source}) "
                f"line {d.line}:{d.column}  " + "; ".join(facts)
            )
            lines.append(f"        {d.snippet}")
    nonzero = {k: v for k, v in result.features.items() if v}
    lines.append(f"\nNon-zero features ({len(nonzero)} of {len(result.features)}):")
    for name, value in nonzero.items():
        lines.append(f"  {name:<40} {value}")
    return "\n".join(lines)


def describe_dictionary(markdown: bool = False) -> str:
    """The feature list (order = vector order) as text or a Markdown table."""
    rules = load_rules()
    if markdown:
        return _md_table(
            ["#", "feature", "group", "type", "description"],
            [
                [i + 1, f"`{spec.name}`", spec.group, spec.type, spec.description]
                for i, spec in enumerate(rules.features)
            ],
        )
    lines = [f"Feature set {rules.feature_set_version}: {len(rules.features)} features"]
    group = None
    for i, spec in enumerate(rules.features, 1):
        if spec.group != group:
            group = spec.group
            lines.append(f"\n[{group}]")
        lines.append(f"  {i:>2}. {spec.name:<40} {spec.type:<6} {spec.description}")
    return "\n".join(lines)
