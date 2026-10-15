"""Reports for Part 8: the batch summary, one page as text, the vector dictionary.

Part 8: Behavioral intent mapping (sources -> sinks).

    reports/behavior/<version>_summary.json
    reports/behavior/<version>_summary.md

What the summary is for:
- per label: % of pages with each pattern, and with each highest severity;
- flows per label (pages with a flow, with an external flow, to a known
  data-collection endpoint, mean flows per page);
- the 10 most severe findings with their sample ids, to inspect by hand;
- the FALSE-POSITIVE CHECK: every BENIGN page with a critical / high finding.
  Each one is either a real problem in the rules or a label error - both
  matter for the thesis, so they are listed, never hidden;
- timing.
Descriptive only: the verdict is Part 9's.
"""

from __future__ import annotations

import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from c2_analyzer.behavior.batch import reports_dir
from c2_analyzer.behavior.rules import PATTERN_IDS, load_behavior_rules, rules_hash
from c2_analyzer.config import get_labels
from c2_analyzer.schemas.behavior import BehaviorResult
from c2_analyzer.utils.io import atomic_write_text, write_json

SEVERITIES = ("critical", "high", "medium", "low")


def _pct(part: float, whole: float) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


def _percentile(values: list[float], share: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(int(share * len(ordered)), len(ordered) - 1)], 2)


def _max_severity(findings: list[dict], pattern: str | None = None) -> str | None:
    scores = [f for f in findings if pattern is None or f["pattern"] == pattern]
    if not scores:
        return None
    return max(scores, key=lambda f: f["severity_score"])["severity"]


def summarize(
    rows: list[dict], results: list[dict], version: str, seconds: float, filters: dict
) -> dict:
    """Everything the report shows, from all stored results (rows) and this run (results)."""
    rules = load_behavior_rules()
    statuses = Counter(r["status"] for r in results)
    labels = [label for label in get_labels() if any(r["label"] == label for r in rows)]
    names = {pattern: str(rules.patterns[pattern]["name"]) for pattern in PATTERN_IDS}

    per_label: dict[str, Any] = {}
    for label in labels:
        own = [r for r in rows if r["label"] == label]
        n = len(own)
        patterns = {}
        for pattern in PATTERN_IDS:
            severities = Counter(_max_severity(r["findings"], pattern) for r in own)
            patterns[pattern] = {
                "pct": _pct(sum(v for k, v in severities.items() if k), n),
                "by_severity": {s: _pct(severities[s], n) for s in SEVERITIES},
            }
        top = Counter(_max_severity(r["findings"]) for r in own)
        flows = [len(r["flows"]) for r in own]
        data_flows = [[f for f in r["flows"] if f["source"] != "decoded_string"] for r in own]
        per_label[label] = {
            "pages": n,
            "patterns": patterns,
            "max_severity_pct": {s: _pct(top[s], n) for s in SEVERITIES}
            | {"none": _pct(top[None], n)},
            "flows": {
                "pages_with_flow": _pct(sum(bool(f) for f in data_flows), n),
                "pages_with_external_flow": _pct(
                    sum(any(x["external"] for x in f) for f in data_flows), n
                ),
                "pages_with_known_endpoint": _pct(
                    sum(any(x["known_endpoint"] for x in f) for f in data_flows), n
                ),
                "mean_flows_per_page": round(statistics.mean(flows), 2) if flows else 0.0,
                "by_source": dict(
                    Counter(x["source"] for f in data_flows for x in f).most_common()
                ),
            },
            "risk_score_mean": (
                round(statistics.mean(r["risk_score"] for r in own), 1) if own else 0.0
            ),
            "risk_score_median": (
                round(statistics.median(r["risk_score"] for r in own), 1) if own else 0.0
            ),
        }

    all_findings = [
        {"sample_id": r["sample_id"], "label": r["label"], **f} for r in rows for f in r["findings"]
    ]
    confidence = {"high": 2, "medium": 1, "low": 0}
    top_findings = sorted(
        (f for f in all_findings if f["severity"] in ("critical", "high")),
        key=lambda f: (-f["severity_score"], -confidence[f["confidence"]], f["sample_id"]),
    )
    seen, top10 = set(), []
    for finding in top_findings:  # one per page, so 10 different pages to inspect
        if finding["sample_id"] in seen:
            continue
        seen.add(finding["sample_id"])
        top10.append(finding)
        if len(top10) == 10:
            break
    benign_fp = [
        {
            "sample_id": r["sample_id"],
            "findings": [
                f"[{f['severity']}] {names[f['pattern']]}: {f['message']}"
                for f in r["findings"]
                if f["severity"] in ("critical", "high")
            ],
        }
        for r in rows
        if r["label"] == "benign"
        and any(f["severity"] in ("critical", "high") for f in r["findings"])
    ]
    benign_total = sum(r["label"] == "benign" for r in rows)

    times = [r["processing_ms"] for r in rows if r.get("processing_ms") is not None]
    steps = Counter()
    for r in rows:
        steps.update(r.get("step_ms") or {})
    return {
        "version": version,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "rules_hash": rules_hash(),
        "feature_set_version": rules.feature_set_version,
        "feature_count": len(rules.features),
        "filters": filters,
        "counts": {
            "run_total": len(results),
            "processed": statuses.get("processed", 0),
            "skipped_unchanged": statuses.get("skipped", 0),
            "failed": statuses.get("failed", 0),
            "part2_processed_now": sum(r.get("part2") == "processed" for r in results),
            "part7_processed_now": sum(r.get("part7") == "processed" for r in results),
            "rows_in_csv": len(rows),
            "truncated": sum(bool(r.get("truncated")) for r in rows),
            "with_errors": sum(bool(r.get("errors")) for r in rows),
        },
        "failures": [
            {"sample_id": r["sample_id"], "error": r.get("error", "")}
            for r in results
            if r["status"] == "failed"
        ],
        "labels": labels,
        "pattern_names": names,
        "per_label": per_label,
        "top_findings": top10,
        "benign_false_positive_check": {
            "benign_pages": benign_total,
            "pages_with_critical_or_high": len(benign_fp),
            "pct": _pct(len(benign_fp), benign_total),
            "pages": benign_fp,
        },
        "timing": {
            "pages_timed": len(times),
            "avg_ms": round(statistics.mean(times), 1) if times else 0.0,
            "median_ms": round(statistics.median(times), 1) if times else 0.0,
            "p95_ms": _percentile(times, 0.95),
            "max_ms": round(max(times), 1) if times else 0.0,
            "wall_seconds": round(seconds, 1),
            "step_avg_ms": {k: round(v / len(rows), 1) for k, v in steps.items()} if rows else {},
        },
    }


# ---- markdown ---------------------------------------------------------------------------


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += [
        "| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |" for row in rows
    ]
    return lines


def render_markdown(summary: dict) -> str:
    labels, per_label, names = summary["labels"], summary["per_label"], summary["pattern_names"]
    counts, timing = summary["counts"], summary["timing"]
    lines = [
        f"# Behavioral intent mapping (Part 8) - {summary['version']}",
        "",
        f"Created {summary['created_at']} · intent vector `{summary['feature_set_version']}` "
        f"({summary['feature_count']} features) · rules `{summary['rules_hash'][:12]}…`. "
        "Descriptive only: findings are evidence with a severity; the verdict is Part 9's.",
        "",
        f"Pages: {counts['rows_in_csv']} (this run: processed {counts['processed']}, unchanged "
        f"{counts['skipped_unchanged']}, failed {counts['failed']}; Part 2 run for "
        f"{counts['part2_processed_now']}, Part 7 for {counts['part7_processed_now']}). Truncated "
        f"(a cap / time budget hit): {counts['truncated']}; pages with script errors: "
        f"{counts['with_errors']}.",
        "",
        "## % of pages with each pattern (any severity)",
        "",
    ]
    rows = [["(pages)"] + [per_label[label]["pages"] for label in labels]]
    for pattern in PATTERN_IDS:
        rows.append(
            [names[pattern]]
            + [f"{per_label[lab]['patterns'][pattern]['pct']:.1f}" for lab in labels]
        )
    lines += _table(["pattern"] + labels, rows)
    lines += ["", "## % of pages by highest severity", ""]
    rows = [
        [severity] + [f"{per_label[lab]['max_severity_pct'][severity]:.1f}" for lab in labels]
        for severity in (*SEVERITIES, "none")
    ]
    rows.append(["mean risk score"] + [per_label[lab]["risk_score_mean"] for lab in labels])
    lines += _table(["highest severity"] + labels, rows)
    lines += ["", "## Pattern × severity (% of pages, critical / high / medium / low)", ""]
    rows = []
    for pattern in PATTERN_IDS:
        cells = []
        for label in labels:
            by = per_label[label]["patterns"][pattern]["by_severity"]
            cells.append(" / ".join(f"{by[s]:.0f}" for s in SEVERITIES))
        rows.append([names[pattern]] + cells)
    lines += _table(["pattern"] + labels, rows)
    lines += ["", "## Flows (source → sink)", ""]
    rows = []
    for key, title in (
        ("pages_with_flow", "% pages with a tainted flow"),
        ("pages_with_external_flow", "% pages with a flow to another site"),
        ("pages_with_known_endpoint", "% pages with a flow to a known endpoint"),
        ("mean_flows_per_page", "mean flows per page"),
    ):
        rows.append([title] + [per_label[lab]["flows"][key] for lab in labels])
    lines += _table(["flows"] + labels, rows)
    lines += ["", "Flows by source (all pages of the label):", ""]
    for label in labels:
        sources = per_label[label]["flows"]["by_source"]
        text = ", ".join(f"{k} {v}" for k, v in sources.items()) or "none"
        lines.append(f"- {label}: {text}")

    lines += ["", "## Top 10 critical / high findings (one per page - inspect these)", ""]
    lines += (
        _table(
            ["sample_id", "label", "severity", "confidence", "pattern", "message"],
            [
                [
                    f["sample_id"],
                    f["label"],
                    f["severity"],
                    f["confidence"],
                    names[f["pattern"]],
                    f["message"],
                ]
                for f in summary["top_findings"]
            ],
        )
        if summary["top_findings"]
        else ["None."]
    )
    check = summary["benign_false_positive_check"]
    lines += [
        "",
        "## False-positive check: benign pages with a critical / high finding",
        "",
        f"{check['pages_with_critical_or_high']} of {check['benign_pages']} benign pages "
        f"({check['pct']} %). Each is either a rule problem or a label error - review them.",
        "",
    ]
    for page in check["pages"]:
        lines.append(f"- **{page['sample_id']}**")
        lines += [f"  - {text}" for text in page["findings"]]
    if not check["pages"]:
        lines.append("None.")
    lines += [
        "",
        "## Timing",
        "",
        f"Per page: avg {timing['avg_ms']} ms, median {timing['median_ms']} ms, p95 "
        f"{timing['p95_ms']} ms, max {timing['max_ms']} ms ({timing['pages_timed']} pages); wall "
        f"{timing['wall_seconds']} s for this run. Average per step (ms): "
        + ", ".join(f"{k} {v}" for k, v in timing["step_avg_ms"].items())
        + ".",
        "",
    ]
    if summary["failures"]:
        lines += ["## Failures", ""] + [
            f"- {f['sample_id']}: {f['error']}" for f in summary["failures"]
        ]
    lines += [
        "",
        "Reproduce: `python scripts/map_behavior.py run --version " + summary["version"] + "`",
        "",
    ]
    return "\n".join(lines)


def write_report(summary: dict, out_dir: Path | None = None) -> list[Path]:
    folder = out_dir or reports_dir()
    folder.mkdir(parents=True, exist_ok=True)
    json_path = folder / f"{summary['version']}_summary.json"
    md_path = folder / f"{summary['version']}_summary.md"
    write_json(summary, json_path)
    atomic_write_text(render_markdown(summary), md_path)
    return [json_path, md_path]


# ---- one page as text ---------------------------------------------------------------------


def describe_result(result: BehaviorResult, label: str | None = None) -> str:
    """Readable text: findings with numbered evidence chains, flows, sources / sinks, vector."""
    meta, summary = result.meta, result.summary
    lines = [
        f"{meta.sample_id or 'page'}"
        + (f" (label: {label})" if label else "")
        + f" - {meta.page_url or 'no URL'}",
        f"Behavior risk score {result.behavior_risk_score:.0f}/100 (descriptive) | "
        f"{summary.scripts_analyzed} script(s) with an AST, {summary.scripts_lexical} regex-only, "
        f"{summary.library_scripts_skipped} library skipped | {summary.sources_total} sources, "
        f"{summary.sinks_total} sinks, {summary.flows_total} flows | {meta.processing_ms} ms",
    ]
    if meta.warnings:
        lines.append("Warnings: " + "; ".join(meta.warnings))
    if result.errors:
        lines.append("Errors: " + "; ".join(result.errors))
    lines += ["", f"Findings ({len(result.findings)}):"]
    if not result.findings:
        lines.append("  none")
    for number, finding in enumerate(result.findings, 1):
        where = f" [script {finding.script_index}]" if finding.script_index is not None else ""
        lines.append(
            f"{number}. [{finding.severity.upper()}] {finding.name} ({finding.variant}, "
            f"confidence {finding.confidence}){where}"
        )
        lines.append(f"   {finding.message}")
        for factor in finding.factors:
            lines.append(f"   + {factor}")
        for step_number, item in enumerate(finding.evidence, 1):
            place = (
                f"script {item.script_index} line {item.line}"
                if item.script_index is not None and item.line
                else ("HTML" if item.kind == "html" else f"script {item.script_index}")
            )
            note = f"  ({item.note})" if item.note else ""
            lines.append(f"     {step_number}. {place}: {item.code}{note}")
    lines += ["", f"Flows ({len(result.flows)}):"]
    for flow in result.flows[:30]:
        where = (
            flow.known_endpoint
            or flow.sink_url_domain
            or ("unknown destination" if flow.sink_is_external is None else "-")
        )
        lines.append(
            f"  #{flow.id} {flow.source_id} -> {flow.sink_id} ({flow.sink_api}, {where}) "
            f"{len(flow.path)} steps, confidence {flow.confidence}"
            + (f", encoded {'/'.join(flow.encodings)}" if flow.encoded else "")
        )
    if len(result.flows) > 30:
        lines.append(f"  ... {len(result.flows) - 30} more")
    lines += [
        "",
        "Sources: " + (", ".join(f"{k} {v}" for k, v in summary.sources_by_id.items()) or "none"),
        "Sinks:   " + (", ".join(f"{k} {v}" for k, v in summary.sinks_by_id.items()) or "none"),
        "",
        "Intent vector (non-zero): "
        + (", ".join(f"{k}={v}" for k, v in result.intent_vector.items() if v) or "all zero"),
    ]
    return "\n".join(lines)


def describe_dictionary(markdown: bool = False) -> str:
    """The intent vector (behavior_features.yaml) + the pattern catalogue."""
    rules = load_behavior_rules()
    if markdown:
        lines = [
            f"# Behavioral intent vector `{rules.feature_set_version}` "
            f"({len(rules.features)} features)",
            "",
        ]
        lines += _table(
            ["#", "feature", "group", "type", "description"],
            [
                [i + 1, f"`{s.name}`", s.group, s.type, s.description]
                for i, s in enumerate(rules.features)
            ],
        )
        lines += ["", "## Patterns", ""]
        rows = []
        for pattern in PATTERN_IDS:
            spec = rules.patterns[pattern]
            variants = ", ".join(f"{k} ({v['severity']})" for k, v in spec["variants"].items())
            rows.append([f"`{pattern}`", spec["name"], spec["description"], variants])
        lines += _table(["id", "name", "description", "variants (severity)"], rows)
        return "\n".join(lines)
    lines = [f"Intent vector {rules.feature_set_version}: {len(rules.features)} features"]
    group = None
    for i, spec in enumerate(rules.features, 1):
        if spec.group != group:
            group = spec.group
            lines.append(f"\n[{group}]")
        lines.append(f"{i:3d}. {spec.name:<40} {spec.type:<7} {spec.description}")
    lines.append("\nPatterns:")
    for pattern in PATTERN_IDS:
        spec = rules.patterns[pattern]
        variants = ", ".join(f"{k}={v['severity']}" for k, v in spec["variants"].items())
        lines.append(f"  {pattern:<28} {variants}")
    return "\n".join(lines)
