"""Part 7 pipeline: ParsedPage -> JsAnalysisResult (detections + feature vector).

Part 7: Static JavaScript intent analyzer.

One entry point, ``analyze_js(page)``, for dataset samples (batch.py) and the
API (``js_analysis_for_html``, Part 9) - the same code gives the same answer.

For every piece of JavaScript Part 2 found (inline scripts, event handlers,
javascript: URLs):
  1. recognise library code (libraries.py) - tagged, not counted as page-own;
  2. parse with tree-sitter under the safety limits (ast_parser.py);
  3. run the AST detectors (detectors.py), or the lexical fallback
     (lexical_scanner.py, confidence="low") if the tree is unusable;
  4. measure obfuscation statistics (obfuscation.py, descriptive);
then list external <script src> references (reference level only), count
detections per API (page-own vs library) and build the fixed feature vector.

Each script is isolated: an unexpected error in one is recorded in
``meta.errors`` and the rest of the page is still analysed. Nothing here runs
JavaScript, and nothing is downloaded.
"""

from __future__ import annotations

import time
from collections import Counter

from c2_analyzer.js_analyzer.ast_parser import parse_js, parser_version
from c2_analyzer.js_analyzer.detectors import PageUrls, ScriptDetector, safe_snippet
from c2_analyzer.js_analyzer.extractor import CodeUnit, collect_scripts, external_scripts
from c2_analyzer.js_analyzer.features import build_features
from c2_analyzer.js_analyzer.lexical_scanner import scan
from c2_analyzer.js_analyzer.libraries import identify_inline
from c2_analyzer.js_analyzer.obfuscation import compute_stats
from c2_analyzer.js_analyzer.rules import Rules, load_rules, rules_hash
from c2_analyzer.preprocessing.loader import from_string
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.js import (
    ApiCount,
    Detection,
    JsAnalysisResult,
    JsMeta,
    JsSummary,
    ScriptInfo,
)
from c2_analyzer.schemas.parsed_page import ParsedPage

LIMITATIONS = [
    "External <script src> files are not downloaded: only their address is analysed (static mode).",
    "Values computed at run time (window[a + b], strings built in loops) are not resolved.",
    "Aliases (var e = eval) are followed within one script, in source order, without scopes.",
    "Code that only exists after decoding (eval(atob('...'))) is reported, not analysed again.",
    "Part 7 reports API usage only; whether it is malicious is decided by Part 8.",
]
FLAG_RULES = {
    "code_execution": lambda f: f["eval_count"]
    + f["function_constructor_count"]
    + f["string_timer_count"]
    > 0,
    "html_injection": lambda f: f["document_write_count"] + f["innerhtml_assign_count"] > 0,
    "network_request": lambda f: f["fetch_count"]
    + f["beacon_count"]
    + f["websocket_count"]
    + f["xhr_count"]
    > 0,
    "external_request": lambda f: f["external_request_count"] > 0,
    "form_submission_from_code": lambda f: f["form_submit_count"] + f["form_action_assign_count"]
    > 0,
    "redirect": lambda f: f["redirect_count"] > 0,
    "external_redirect": lambda f: f["external_redirect_count"] > 0,
    "cookie_access": lambda f: f["cookie_read_count"] + f["cookie_write_count"] > 0,
    "storage_access": lambda f: f["storage_read_count"] + f["storage_write_count"] > 0,
    "clipboard_write": lambda f: f["clipboard_write_count"] > 0,
    "clipboard_read": lambda f: f["clipboard_read_count"] > 0,
    "credential_value_read": lambda f: f["credential_value_read_count"] > 0,
    "key_listener": lambda f: f["key_listener_count"] > 0,
    "contextmenu_block": lambda f: f["contextmenu_block_count"] > 0,
    "download_trigger": lambda f: f["download_trigger_count"] > 0,
    "obfuscation_signature": lambda f: f["obfuscation_signature_count"] > 0,
    "suspicious_external_script": lambda f: f["external_script_suspicious_host_count"] > 0,
    "parse_fallback_used": lambda f: f["parse_failure_ratio"] > 0,
}


def _handler_listener(unit: CodeUnit, index: int, rules: Rules) -> Detection | None:
    """``<body oncontextmenu="return false">``: the attribute itself is a listener."""
    if unit.source != "event_handler" or not unit.attribute:
        return None
    event = unit.attribute[2:]
    api = (rules.lists.get("listener_events") or {}).get(event)
    if api is None:
        return None
    return Detection(
        api=api,
        category=rules.category(api),
        source="event_handler",
        script_index=index,
        line=1,
        column=1,
        end_line=1,
        start_byte=0,
        end_byte=len(unit.text.encode("utf-8", errors="replace")),
        access="listener",
        snippet=safe_snippet(f'{unit.attribute}="{unit.text}"'),
        callee=unit.attribute,
        event_type=event,
        target=f"<{unit.tag}>",
    )


def analyze_unit(
    unit: CodeUnit, index: int, rules: Rules, urls: PageUrls
) -> tuple[ScriptInfo, list[Detection], dict[str, float]]:
    """Parse + detect + measure one piece of JavaScript."""
    limits = rules.limits
    timing = {"parse": 0.0, "detect": 0.0, "stats": 0.0}
    library = identify_inline(unit.text, rules) if unit.source == "inline" else None
    outcome = parse_js(
        unit.text,
        max_bytes=int(limits["max_script_bytes"]),
        timeout_ms=int(limits["parse_timeout_ms"]),
        max_error_ratio=float(limits["max_error_ratio"]),
    )
    timing["parse"] = outcome.parse_ms
    started = time.perf_counter()
    collector = None
    depth_capped = False
    if outcome.usable:
        detector = ScriptDetector(
            rules, index, unit.source, outcome.source, urls, in_library=library is not None
        )
        detections = detector.run(outcome.tree, int(limits["max_ast_depth"]))
        collector, depth_capped = detector.obfuscation, detector.depth_capped
    else:
        detections = scan(outcome.text, rules, index, unit.source, urls, library is not None)
    extra = _handler_listener(unit, index, rules)
    if extra is not None:
        detections.insert(0, extra)
    timing["detect"] = round((time.perf_counter() - started) * 1000, 2)
    started = time.perf_counter()
    stats = compute_stats(outcome.text, collector, rules.raw["js_rules"].get("obfuscation"))
    timing["stats"] = round((time.perf_counter() - started) * 1000, 2)
    info = ScriptInfo(
        index=index,
        source=unit.source,
        origin=unit.origin,
        part2_index=unit.part2_index,
        chars=unit.chars,
        analyzed_chars=len(outcome.text),
        truncated=outcome.truncated or unit.capped_by_part2,
        parser="tree-sitter" if outcome.usable else "lexical",
        parsed_ok=outcome.usable,
        has_error=outcome.has_error,
        error_ratio=outcome.error_ratio,
        timed_out=outcome.timed_out,
        depth_capped=depth_capped,
        parse_ms=outcome.parse_ms,
        library=library,
        detections=len(detections),
        obfuscation=stats,
        note=outcome.error,
    )
    return info, detections, timing


def _counts(detections: list[Detection]) -> list[ApiCount]:
    table: dict[str, ApiCount] = {}
    for detection in detections:
        row = table.setdefault(
            detection.api, ApiCount(api=detection.api, category=detection.category)
        )
        if detection.in_library:
            row.library += 1
        else:
            row.page_own += 1
    return sorted(table.values(), key=lambda row: (-row.page_own, -row.library, row.api))


def analyze_js(page: ParsedPage) -> JsAnalysisResult:
    """Static JavaScript analysis of one page (never raises for page content)."""
    started = time.perf_counter()
    rules = load_rules()
    limits = rules.limits
    urls = PageUrls(page.meta.page_url, page.meta.base_url)
    errors: list[str] = []
    warnings: list[str] = []
    step_ms = {"extract": 0.0, "parse": 0.0, "detect": 0.0, "stats": 0.0, "features": 0.0}

    step = time.perf_counter()
    units = collect_scripts(page)
    external = external_scripts(page, rules)
    step_ms["extract"] = round((time.perf_counter() - step) * 1000, 2)

    scripts: list[ScriptInfo] = []
    detections: list[Detection] = []
    budget = int(limits["max_page_bytes"])
    for index, unit in enumerate(units):
        if index >= int(limits["max_scripts_per_page"]) or budget <= 0:
            scripts.append(
                ScriptInfo(
                    index=index,
                    source=unit.source,
                    origin=unit.origin,
                    part2_index=unit.part2_index,
                    chars=unit.chars,
                    analyzed_chars=0,
                    parser="skipped",
                    parsed_ok=False,
                    note="not analysed: page limit (max_scripts_per_page / max_page_bytes)",
                )
            )
            continue
        try:
            info, found, timing = analyze_unit(unit, index, rules, urls)
        except Exception as error:  # noqa: BLE001 - one script must not lose the page
            errors.append(f"{unit.origin}: {type(error).__name__}: {error}")
            scripts.append(
                ScriptInfo(
                    index=index,
                    source=unit.source,
                    origin=unit.origin,
                    part2_index=unit.part2_index,
                    chars=unit.chars,
                    analyzed_chars=0,
                    parser="skipped",
                    parsed_ok=False,
                    note=f"analysis failed: {type(error).__name__}",
                )
            )
            continue
        budget -= len(unit.text)
        scripts.append(info)
        detections.extend(found)
        for key, value in timing.items():
            step_ms[key] = round(step_ms[key] + value, 2)
    skipped = sum(s.parser == "skipped" and s.note and "page limit" in s.note for s in scripts)
    if skipped:
        warnings.append(f"{skipped} script(s) not analysed (page limits)")
    if any(s.timed_out for s in scripts):
        warnings.append("a parse hit the time limit: lexical fallback used")
    if any(s.depth_capped for s in scripts):
        warnings.append("very deep nesting: the walk stopped at max_ast_depth")

    step = time.perf_counter()
    features = build_features(rules, scripts, external, detections)
    counts = _counts(detections)
    own = Counter(d.category for d in detections if not d.in_library)
    library = Counter(d.category for d in detections if d.in_library)
    step_ms["features"] = round((time.perf_counter() - step) * 1000, 2)

    cap = int(limits["max_detections_per_page"])
    stored = detections[:cap]
    if len(detections) > cap:
        warnings.append(f"{len(detections)} detections, first {cap} stored (counts are complete)")
    summary = JsSummary(
        scripts_analyzed=sum(s.parser != "skipped" for s in scripts),
        scripts_lexical=sum(s.parser == "lexical" for s in scripts),
        library_scripts=sum(s.library is not None for s in scripts),
        detections_total=len(detections),
        detections_page_own=sum(not d.in_library for d in detections),
        detections_stored=len(stored),
        categories_page_own=dict(sorted(own.items())),
        categories_library=dict(sorted(library.items())),
        flags={name: bool(rule(features)) for name, rule in FLAG_RULES.items()},
        libraries=sorted({s.library for s in scripts if s.library}),
    )
    meta = JsMeta(
        sample_id=page.meta.sample_id,
        dataset_version=page.meta.dataset_version,
        page_url=page.meta.page_url,
        base_url=page.meta.base_url,
        source_sha256=page.meta.source_sha256,
        rules_hash=rules_hash(),
        parser=parser_version(),
        processing_ms=round((time.perf_counter() - started) * 1000, 2),
        step_ms=step_ms,
        errors=errors,
        warnings=warnings,
    )
    return JsAnalysisResult(
        meta=meta,
        feature_set_version=rules.feature_set_version,
        features=features,
        summary=summary,
        scripts=scripts,
        external_scripts=external,
        detections=stored,
        counts=counts,
        limitations=LIMITATIONS,
    )


def js_analysis_for_html(html: str, url: str | None = None) -> JsAnalysisResult:
    """The API path (Part 9): HTML string -> Part 2 -> Part 7 (``url`` is never fetched)."""
    return analyze_js(preprocess(from_string(html, url)))
