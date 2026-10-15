"""Part 8 pipeline: (ParsedPage, JsAnalysisResult) -> BehaviorResult (task 12).

Part 8: Behavioral intent mapping (sources -> sinks).

One entry point, ``map_behavior(page, js_result)``, for dataset samples
(batch.py) and the API (``behavior_for_html``, Part 9) - same code, same
answer. Steps:
  1. code_index    re-parse the page-own scripts with Part 7's parser, map
                   Part 7's detections to AST nodes, index scopes / functions;
  2. triggers      who runs each piece of code (page load, timer, click ...);
  3. sources_sinks sensitive sources and dangerous sinks (tasks 1-2);
  4. dataflow      source -> sink flows with evidence chains (task 3);
  5. patterns      behavioral patterns with severity and messages (tasks 4-10);
  6. intent_vector fixed-order vector + risk score + top lines (task 11).
Nothing runs JavaScript, nothing is downloaded. Library scripts are skipped.
A failing script is recorded in ``errors`` and the rest of the page is still
analysed; caps and time budgets mark the result ``truncated``.
"""

from __future__ import annotations

import time
from collections import Counter

from c2_analyzer.behavior.code_index import (
    Indexer,
    ScriptCtx,
    functions_by_name,
    page_uses,
)
from c2_analyzer.behavior.dataflow import RawFlow, TaintEngine
from c2_analyzer.behavior.intent_vector import build_vector, risk_score, top_lines
from c2_analyzer.behavior.patterns import PageFacts, PatternMatcher
from c2_analyzer.behavior.rules import load_behavior_rules, rules_hash
from c2_analyzer.behavior.sources_sinks import CatalogueBuilder, SinkRef, SourceRef
from c2_analyzer.behavior.triggers import TriggerResolver
from c2_analyzer.js_analyzer.detectors import PageUrls
from c2_analyzer.js_analyzer.extractor import collect_scripts
from c2_analyzer.js_analyzer.pipeline import analyze_js
from c2_analyzer.js_analyzer.rules import load_rules as load_js_rules
from c2_analyzer.js_analyzer.rules import rules_hash as js_rules_hash
from c2_analyzer.preprocessing.loader import from_string
from c2_analyzer.preprocessing.pipeline import preprocess
from c2_analyzer.schemas.behavior import (
    BehaviorMeta,
    BehaviorResult,
    BehaviorSummary,
    Flow,
    FlowStep,
    SinkHit,
    SourceHit,
)
from c2_analyzer.schemas.js import Detection, JsAnalysisResult
from c2_analyzer.schemas.parsed_page import ParsedPage

LIMITATIONS = [
    "Static only: no JavaScript is executed and external <script src> files are never fetched "
    "- what they do is not seen.",
    "Taint is tracked per variable (not per object field) within the page; data passed through "
    "the DOM, dynamic property names (obj[k]) or strings built at run time is not followed.",
    "Functions are matched by name across the page's scripts; scripts share data only through "
    "global names. Block scopes are treated as function scopes.",
    "Scripts Part 7 could only scan with regexes give co-occurrence evidence only "
    "(confidence low).",
    "Findings are descriptive evidence with a severity; the verdict is decided by Part 9.",
]
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _flow_confidence(raw: RawFlow) -> str:
    label = raw.label
    if raw.lexical or label.low or raw.source.confidence == "low" or raw.sink.confidence == "low":
        return "low"
    if label.via_function or label.via_object or len(label.steps) > 4:
        return "medium"
    return "high"


def _destination_note(sink: SinkRef) -> str:
    if sink.endpoint:
        return f"{sink.api} -> {sink.endpoint} ({sink.url_domain or sink.url})"
    if sink.url_domain:
        where = "external" if sink.is_external else "own site"
        return f"{sink.api} -> {sink.url_domain} ({where})"
    if sink.is_external is None and sink.sink_id.startswith(("network", "redirect")):
        return f"{sink.api} -> address built at run time"
    return sink.api


def _flows(raws: list[RawFlow], limit: int) -> tuple[list[tuple[Flow, RawFlow]], bool]:
    raws = sorted(raws, key=lambda r: (r.sink.id, r.source.id))
    if len(raws) > limit:
        # keep the most sensitive / confident ones when a page has very many flows
        rank = {"high": 0, "medium": 1, "low": 2}
        raws = sorted(raws, key=lambda r: (rank[r.source.sensitivity], r.sink.id, r.source.id))
        raws = sorted(raws[:limit], key=lambda r: (r.sink.id, r.source.id))
        truncated = True
    else:
        truncated = False
    out = []
    for number, raw in enumerate(raws):
        sink, label = raw.sink, raw.label
        path = [
            FlowStep(
                step=step.kind,
                script_index=step.script,
                line=step.line,
                column=step.column,
                code=step.code,
                note=step.note,
            )
            for step in label.steps
        ]
        path.append(
            FlowStep(
                step="sink",
                script_index=sink.ctx.index if sink.ctx is not None else -1,
                line=sink.line,
                column=sink.column,
                code=sink.code,
                note=_destination_note(sink),
            )
        )
        out.append(
            (
                Flow(
                    id=number,
                    source_id=raw.source.source_id,
                    source_ref=raw.source.id,
                    sink_id=sink.sink_id,
                    sink_ref=sink.id,
                    sink_api=sink.api,
                    script_index=sink.ctx.index if sink.ctx is not None else -1,
                    path=path,
                    confidence=_flow_confidence(raw),
                    encoded=bool(label.encodings),
                    encodings=list(label.encodings),
                    via_function=label.via_function,
                    sink_url_domain=sink.url_domain,
                    sink_is_external=sink.is_external,
                    sink_is_known_exfil_endpoint=sink.endpoint is not None,
                    known_endpoint=sink.endpoint,
                    truncated=label.truncated,
                ),
                raw,
            )
        )
    return out, truncated


def _source_hit(ref: SourceRef) -> SourceHit:
    return SourceHit(
        id=ref.id,
        source_id=ref.source_id,
        sensitivity=ref.sensitivity,
        api=ref.api,
        script_index=ref.ctx.index if ref.ctx is not None else -1,
        line=ref.line,
        column=ref.column,
        code=ref.code,
        detail=ref.detail,
        confidence="low" if ref.confidence == "low" else "high",
    )


def _sink_hit(ref: SinkRef) -> SinkHit:
    trigger = ref.trigger
    return SinkHit(
        id=ref.id,
        sink_id=ref.sink_id,
        api=ref.api,
        script_index=ref.ctx.index if ref.ctx is not None else -1,
        line=ref.line,
        column=ref.column,
        code=ref.code,
        url=ref.url,
        url_domain=ref.url_domain,
        is_external=ref.is_external,
        known_exfil_endpoint=ref.endpoint,
        trigger=trigger.kind if trigger is not None else "unknown",
        trigger_reason=trigger.reason if trigger is not None else None,
        confidence="low" if ref.confidence == "low" else "high",
    )


def map_behavior(page: ParsedPage, js_result: JsAnalysisResult) -> BehaviorResult:
    """Behavioral intent of one page from its ParsedPage and Part 7 result."""
    started = time.perf_counter()
    rules = load_behavior_rules()
    js_rules = load_js_rules()
    errors: list[str] = []
    warnings: list[str] = []
    step_ms: dict[str, float] = {}
    if (
        page.meta.source_sha256
        and js_result.meta.source_sha256
        and page.meta.source_sha256 != js_result.meta.source_sha256
    ):
        raise ValueError("the Part 7 result was made from another page (source_sha256 differs)")
    if js_result.meta.rules_hash != js_rules_hash():
        warnings.append("the Part 7 result was made with other JS rules (re-run analyze_js.py)")
    urls = PageUrls(page.meta.page_url, page.meta.base_url)

    # 1. index the page-own scripts -------------------------------------------------
    step = time.perf_counter()
    units = collect_scripts(page)
    if len(units) != len(js_result.scripts) or any(
        unit.source != info.source for unit, info in zip(units, js_result.scripts, strict=False)
    ):
        raise ValueError("the Part 7 result does not match this page's scripts")
    complete = js_result.summary.detections_stored >= js_result.summary.detections_total
    by_script: dict[int, list[Detection]] = {}
    for detection in js_result.detections:
        by_script.setdefault(detection.script_index, []).append(detection)
    sources = rules.sources
    watched = frozenset(
        list(sources["page_url"].get("paths") or [])
        + list(sources["fingerprint"].get("paths") or [])
    )
    indexer = Indexer(
        js_rules, urls, frozenset(sources["keystrokes"].get("event_properties") or []), watched
    )
    contexts: list[ScriptCtx] = []
    library_skipped = 0
    for index, (unit, info) in enumerate(zip(units, js_result.scripts, strict=True)):
        if info.library is not None:
            library_skipped += 1
            continue
        if info.parser == "skipped":
            continue
        try:
            detections = by_script.get(index, []) if complete else None
            contexts.append(indexer.build(index, info, unit, detections))
        except Exception as error:  # noqa: BLE001 - one script must not lose the page
            errors.append(f"{info.origin}: {type(error).__name__}: {error}")
    if any(ctx.depth_capped for ctx in contexts):
        warnings.append("very deep nesting: the index stopped at max_ast_depth")
    if not complete:
        warnings.append("Part 7 stored a cut detection list: scripts were detected again")
    registry = functions_by_name(contexts)
    resolver = TriggerResolver(
        {ctx.index: ctx for ctx in contexts}, registry, page_uses(contexts), rules.events
    )
    step_ms["index"] = round((time.perf_counter() - step) * 1000, 2)

    # 2-3. sources and sinks -----------------------------------------------------------
    step = time.perf_counter()
    builder = CatalogueBuilder(rules, page, urls, contexts, registry, resolver)
    catalogue = builder.build()
    step_ms["sources_sinks"] = round((time.perf_counter() - step) * 1000, 2)

    # 4. flows -------------------------------------------------------------------------
    step = time.perf_counter()
    engine = TaintEngine(rules, contexts, catalogue, registry).run()
    warnings += engine.warnings
    flows, cut = _flows(engine.flows, int(rules.limit("max_flows")))
    if cut:
        warnings.append(
            f"{len(engine.flows)} flows, the {rules.limit('max_flows')} most sensitive kept"
        )
    step_ms["dataflow"] = round((time.perf_counter() - step) * 1000, 2)

    # 5. patterns ----------------------------------------------------------------------
    step = time.perf_counter()
    facts = PageFacts(
        rules=rules,
        js=js_result,
        contexts={ctx.index: ctx for ctx in contexts},
        catalogue=catalogue,
        flows=flows,
        fields=builder.fields,
    )
    findings = PatternMatcher(facts, resolver).run()
    step_ms["patterns"] = round((time.perf_counter() - step) * 1000, 2)

    # 6. vector ------------------------------------------------------------------------
    step = time.perf_counter()
    score = risk_score(findings, rules.risk_weights, rules.risk_cap)
    flow_list = [flow for flow, _ in flows]
    vector = build_vector(rules, findings, flow_list, score)
    step_ms["vector"] = round((time.perf_counter() - step) * 1000, 2)

    max_sources, max_sinks = int(rules.limit("max_sources")), int(rules.limit("max_sinks"))
    if len(catalogue.sources) > max_sources or len(catalogue.sinks) > max_sinks:
        warnings.append("very many sources / sinks: the stored lists are cut (counts are complete)")
    truncated = engine.truncated or cut or any(flow.truncated for flow in flow_list)
    severities = Counter(f.severity for f in findings)
    summary = BehaviorSummary(
        scripts_analyzed=sum(not ctx.lexical for ctx in contexts),
        scripts_lexical=sum(ctx.lexical for ctx in contexts),
        library_scripts_skipped=library_skipped,
        sources_total=len(catalogue.sources),
        sinks_total=len(catalogue.sinks),
        flows_total=len(engine.flows),
        sources_by_id=dict(sorted(Counter(s.source_id for s in catalogue.sources).items())),
        sinks_by_id=dict(sorted(Counter(s.sink_id for s in catalogue.sinks).items())),
        findings_by_severity={
            k: severities[k] for k in ("critical", "high", "medium", "low") if severities[k]
        },
        max_severity=findings[0].severity if findings else None,
        passes=engine.passes,
    )
    meta = BehaviorMeta(
        sample_id=page.meta.sample_id,
        dataset_version=page.meta.dataset_version,
        page_url=page.meta.page_url,
        base_url=page.meta.base_url,
        source_sha256=page.meta.source_sha256 or js_result.meta.source_sha256,
        js_rules_hash=js_result.meta.rules_hash,
        rules_hash=rules_hash(),
        processing_ms=round((time.perf_counter() - started) * 1000, 2),
        step_ms=step_ms,
        truncated=truncated,
        warnings=warnings,
    )
    return BehaviorResult(
        meta=meta,
        feature_set_version=rules.feature_set_version,
        summary=summary,
        sources_found=[_source_hit(ref) for ref in catalogue.sources[:max_sources]],
        sinks_found=[_sink_hit(ref) for ref in catalogue.sinks[:max_sinks]],
        flows=flow_list,
        findings=findings,
        intent_vector=vector,
        behavior_risk_score=score,
        top_findings=top_lines(findings),
        errors=errors,
        limitations=LIMITATIONS,
    )


def behavior_for_html(
    html: str, url: str | None = None
) -> tuple[ParsedPage, JsAnalysisResult, BehaviorResult]:
    """The API path (Part 9): HTML -> Part 2 -> Part 7 -> Part 8 (``url`` is never fetched)."""
    page = preprocess(from_string(html, url))
    js_result = analyze_js(page)
    return page, js_result, map_behavior(page, js_result)
