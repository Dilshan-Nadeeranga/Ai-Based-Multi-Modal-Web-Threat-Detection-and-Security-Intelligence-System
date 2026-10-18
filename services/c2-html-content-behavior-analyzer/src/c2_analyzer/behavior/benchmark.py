"""Behavioral intent detection rate on REAL pages (Part 8 evaluation; proposal metric "≥ 90 % TPR").

Why real pages only: the benchmark is `data/benchmarks/behavior_v1/candidates.csv` -
v0.3 pages whose code was READ by a person and labelled per pattern (positive = the code
really does it, negative = it only looks similar). Labels come from reading the code,
never from the detector's own output (that would be circular). No attack snippets are
written for it. Until a reviewer confirms a row (`confirmed=true`) every number is
PRELIMINARY; with a few pages per pattern the Wilson CIs are wide and patterns with too
few positives / negatives are reported as "not measurable".

Ground truth is about BEHAVIOUR, not maliciousness: a benign site that blocks DevTools is
an anti_analysis positive. The detector is never tuned on this set.

Detection rule: a page is "detected" for a pattern when Part 8 returns ANY finding with
that pattern_id ("any" view); the "≥ high" view counts only high / critical findings
(what the Part 9 evidence floor reacts to). Predictions come from the stored Part 8 result
of the frozen version (refused if it is stale - re-run map_behavior.py first).
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

from c2_analyzer.behavior.batch import output_dir, stored_result
from c2_analyzer.config import resolve_path
from c2_analyzer.utils.stats import wilson

BENCHMARK_DIR = Path("data/benchmarks/behavior_v1")
PATTERNS = (
    "credential_exfiltration",
    "keylogging",
    "forced_redirect",
    "clipboard_manipulation",
    "suspicious_download",
    "obfuscated_execution",
    "anti_analysis",
)
MIN_N = 3  # a rate is reported only with at least this many pages behind it
HIGH = {"high", "critical"}
# Reviewer notes printed next to a miss (observations only - the detector is not changed here).
MISS_NOTES = {
    "c2_malware_delivery_000023": (
        "**Possible detector miss** (ClickFix): the PowerShell command is built by string "
        "concatenation, passed through two helper functions into a temporary textarea's value "
        "and copied with execCommand('copy') - the clipboard pattern expects a literal command "
        "reaching a clipboard write. Not changed in this batch."
    ),
    "c2_benign_000009": (
        "**Likely a LABEL error, not a miss:** the page is pages.github.com and the refresh "
        'goes to docs.github.com - the same registrable domain, which the pattern ("to another '
        'site") correctly treats as internal. Suggest relabelling to negative when confirming; '
        "the first-run number above keeps the original label."
    ),
    "c2_phishing_000009": (
        "Expected static-analysis limitation: the endpoint and field names sit in an "
        "_0x string array resolved at run time, so no literal flow exists to follow."
    ),
    "c2_phishing_000043": (
        "The flow runs password -> buildReport() -> sendToTelegram() -> new Image().src with a "
        "URL built from constants; not investigated in this batch (detector unchanged)."
    ),
}


@dataclass
class CaseResult:
    sample_id: str
    pattern: str
    expected: str  # positive | negative
    confirmed: bool
    reason: str
    detected_any: bool = False
    detected_high: bool = False
    severities: list[str] = field(default_factory=list)  # of this pattern's findings
    other_patterns: list[str] = field(default_factory=list)
    error: str | None = None


def load_candidates(path: Path | None = None) -> list[dict]:
    path = path or resolve_path(BENCHMARK_DIR / "candidates.csv")
    with path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    for i, row in enumerate(rows, 2):
        if row["pattern"] not in PATTERNS:
            raise ValueError(f"line {i}: unknown pattern {row['pattern']!r}")
        if row["expected"] not in ("positive", "negative"):
            raise ValueError(f"line {i}: expected must be positive|negative")
    return rows


def manifest_sha(version: str) -> dict[str, str]:
    path = resolve_path(Path("data/metadata/manifests") / f"dataset_{version}.csv")
    with path.open(encoding="utf-8", newline="") as fh:
        return {r["sample_id"]: r["sha256"] for r in csv.DictReader(fh)}


def stored_loader(version: str, results_dir: Path | None = None):
    """sample_id -> the CURRENT stored Part 8 result (None if missing / stale), or a str error."""
    shas = manifest_sha(version)
    results_dir = results_dir or output_dir(version)

    def load(sample_id: str):
        sha = shas.get(sample_id)
        if sha is None:
            return "not in the manifest"
        result = stored_result(results_dir / f"{sample_id}.json", sha)
        return result if result is not None else "no current Part 8 result"

    return load


def evaluate_cases(rows: list[dict], version: str, load=None) -> list[CaseResult]:
    """Detector output for every candidate row (``load`` defaults to the stored results)."""
    load = load or stored_loader(version)
    out = []
    for row in rows:
        case = CaseResult(
            sample_id=row["sample_id"],
            pattern=row["pattern"],
            expected=row["expected"],
            confirmed=str(row.get("confirmed", "")).strip().lower() == "true",
            reason=row.get("reason", ""),
        )
        result = load(case.sample_id)
        if result is None or isinstance(result, str):
            case.error = result or "no current Part 8 result"
            out.append(case)
            continue
        mine = [f for f in result.findings if f.pattern_id == case.pattern]
        case.severities = [f.severity for f in mine]
        case.detected_any = bool(mine)
        case.detected_high = any(f.severity in HIGH for f in mine)
        case.other_patterns = sorted({f.pattern_id for f in result.findings} - {case.pattern})
        out.append(case)
    return out


def _rates(cases: list[CaseResult], view: str) -> dict:
    hit = (lambda c: c.detected_any) if view == "any" else (lambda c: c.detected_high)
    ok = [c for c in cases if c.error is None]
    pos = [c for c in ok if c.expected == "positive"]
    neg = [c for c in ok if c.expected == "negative"]
    tp = sum(hit(c) for c in pos)
    fp = sum(hit(c) for c in neg)
    tpr, fpr, prec = wilson(tp, len(pos)), wilson(fp, len(neg)), wilson(tp, tp + fp)
    return {
        "n_pos": len(pos),
        "n_neg": len(neg),
        "tp": tp,
        "fp": fp,
        "tpr": tpr.as_dict() | {"text": tpr.text(), "measurable": len(pos) >= MIN_N},
        "fpr": fpr.as_dict() | {"text": fpr.text(), "measurable": len(neg) >= MIN_N},
        "precision": prec.as_dict() | {"text": prec.text(), "measurable": tp + fp >= MIN_N},
    }


def summarize(cases: list[CaseResult]) -> dict:
    per = {}
    for pattern in PATTERNS:
        mine = [c for c in cases if c.pattern == pattern]
        per[pattern] = {view: _rates(mine, view) for view in ("any", "high")}
    return {
        "n_cases": len(cases),
        "n_pages": len({c.sample_id for c in cases}),
        "n_confirmed": sum(c.confirmed for c in cases),
        "errors": [{"sample_id": c.sample_id, "error": c.error} for c in cases if c.error],
        "per_pattern": per,
        "overall": {view: _rates(cases, view) for view in ("any", "high")},
        "misses": [
            {
                "sample_id": c.sample_id,
                "pattern": c.pattern,
                "reason": c.reason,
                "other_patterns": c.other_patterns,
            }
            for c in cases
            if c.error is None and c.expected == "positive" and not c.detected_any
        ],
        "false_alarms": [
            {
                "sample_id": c.sample_id,
                "pattern": c.pattern,
                "reason": c.reason,
                "severities": c.severities,
            }
            for c in cases
            if c.error is None and c.expected == "negative" and c.detected_any
        ],
    }


def _cell(rate: dict) -> str:
    return rate["text"] if rate["measurable"] else f"not measurable ({rate['text']})"


def render_markdown(summary: dict, cases: list[CaseResult], version: str, notes: dict) -> str:
    unconfirmed = summary["n_cases"] - summary["n_confirmed"]
    lines = [
        "# Behavioral intent detection - benchmark v1 (real pages)",
        "",
        f"> **PRELIMINARY, UNCONFIRMED, SMALL n.** {summary['n_cases']} labelled cases on "
        f"{summary['n_pages']} real {version} pages; {unconfirmed} of them are not yet confirmed "
        "by a reviewer. Labels come from reading each page's code, not from the detector. "
        "95 % Wilson CIs. A rate is called measurable only with ≥ "
        f"{MIN_N} pages behind it. The detector was NOT tuned on these pages (first run).",
        "",
        "Rule: *detected* = Part 8 returns any finding of that pattern; *≥ high* = only "
        "high / critical findings (what the Part 9 evidence floor uses). FPR is over the "
        "pattern's real look-alike negatives.",
        "",
        "| pattern | pos | neg | TPR (any) | FPR (any) | precision (any) | TPR (≥ high) |",
        "|---|---|---|---|---|---|---|",
    ]
    for pattern, views in summary["per_pattern"].items():
        a, h = views["any"], views["high"]
        lines.append(
            f"| {pattern} | {a['n_pos']} | {a['n_neg']} | {_cell(a['tpr'])} | {_cell(a['fpr'])} "
            f"| {_cell(a['precision'])} | {_cell(h['tpr'])} |"
        )
    a, h = summary["overall"]["any"], summary["overall"]["high"]
    lines += [
        f"| **overall** | {a['n_pos']} | {a['n_neg']} | {_cell(a['tpr'])} | {_cell(a['fpr'])} "
        f"| {_cell(a['precision'])} | {_cell(h['tpr'])} |",
        "",
        "## Coverage gaps",
        "",
    ]
    for pattern, views in summary["per_pattern"].items():
        a = views["any"]
        if a["n_pos"] < MIN_N:
            lines.append(
                f"- **{pattern}**: {a['n_pos']} real positive page(s) - TPR cannot be measured "
                "on real data yet."
            )
    lines += ["", "## Misses (positives not detected)", ""]
    for m in summary["misses"] or [{"sample_id": "none"}]:
        if m["sample_id"] == "none":
            lines.append("- none")
            continue
        extra = notes.get(m["sample_id"], "")
        other = ", ".join(m["other_patterns"]) or "none"
        lines.append(
            f"- `{m['sample_id']}` ({m['pattern']}): {m['reason']}. Other patterns found: "
            f"{other}.{(' ' + extra) if extra else ''}"
        )
    lines += ["", "## False alarms (negatives detected)", ""]
    for f in summary["false_alarms"] or [{"sample_id": "none"}]:
        if f["sample_id"] == "none":
            lines.append("- none")
            continue
        lines.append(
            f"- `{f['sample_id']}` ({f['pattern']}, {', '.join(f['severities'])}): {f['reason']}"
        )
    if summary["errors"]:
        lines += ["", "## Not evaluated", ""]
        lines += [f"- `{e['sample_id']}`: {e['error']}" for e in summary["errors"]]
    lines += [
        "",
        "## All cases",
        "",
        "| sample_id | pattern | expected | detected | severities | confirmed |",
        "|---|---|---|---|---|---|",
    ]
    for c in cases:
        det = "error" if c.error else ("yes" if c.detected_any else "no")
        lines.append(
            f"| `{c.sample_id}` | {c.pattern} | {c.expected} | {det} | "
            f"{', '.join(c.severities) or '-'} | {'yes' if c.confirmed else 'no'} |"
        )
    return "\n".join(lines) + "\n"
