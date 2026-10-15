"""Behavioral intent mapping output (schema behavior_v1).

Part 8: Behavioral intent mapping (sources -> sinks).

Part 8's input is Part 2's ``ParsedPage`` plus Part 7's ``JsAnalysisResult``.
Its output answers "what is this page's code trying to do?":
- ``sources_found``  sensitive data the code reads (credential fields, keys, cookies ...);
- ``sinks_found``    places data can go (requests, redirects, clipboard, eval ...);
- ``flows``          a source that REACHES a sink, with the evidence chain a person
                     can follow (source line -> assignments -> sink line);
- ``findings``       behavioral patterns (credential exfiltration, forced redirect,
                     ClickFix ...) with severity, a plain-English message and evidence;
- ``intent_vector``  the fixed-order numbers of configs/behavior_features.yaml.
Part 9 turns findings + evidence into explanations (proposal TE4).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "behavior_v1"

Severity = Literal["critical", "high", "medium", "low"]
Confidence = Literal["high", "medium", "low"]
Sensitivity = Literal["high", "medium", "low"]
StepKind = Literal["source", "assign", "concat", "call", "encode", "sink"]
TriggerKind = Literal["auto", "user", "unknown"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FlowStep(_Model):
    """One step of an evidence chain (what a person reads to follow the data)."""

    step: StepKind
    script_index: int
    line: int
    column: int
    code: str  # <= 120 chars, single line, PII-masked
    note: str | None = None  # "pwd", "argument p of send()", "btoa (base64)"


class SourceHit(_Model):
    """Sensitive data read by page-own code."""

    id: int
    source_id: str  # configs/sources_sinks.yaml sources.<id>
    sensitivity: Sensitivity
    api: str  # Part 7 api id, or "part8:<matcher>" for sources Part 7 does not record
    script_index: int
    line: int
    column: int
    code: str
    detail: str | None = None  # field class / selector / property
    confidence: Confidence = "high"


class SinkHit(_Model):
    """A place page-own code sends / runs / writes data."""

    id: int
    sink_id: str  # configs/sources_sinks.yaml sinks.<id>
    api: str
    script_index: int
    line: int
    column: int
    code: str
    url: str | None = None  # resolved (literal or string constant), PII-masked
    url_domain: str | None = None
    is_external: bool | None = None  # None = destination built at run time
    known_exfil_endpoint: str | None = None  # name from sources_sinks.yaml exfil_endpoints
    trigger: TriggerKind = "unknown"
    trigger_reason: str | None = None  # "top-level code (runs on page load)", "click listener"
    confidence: Confidence = "high"


class Flow(_Model):
    """A source that reaches a sink (lightweight intra-page taint analysis)."""

    id: int
    source_id: str
    source_ref: int  # SourceHit.id
    sink_id: str
    sink_ref: int  # SinkHit.id
    sink_api: str
    script_index: int  # of the sink
    path: list[FlowStep] = Field(default_factory=list)
    confidence: Confidence = "high"  # high direct/short, medium via function/object, low regex-only
    encoded: bool = False
    encodings: list[str] = Field(default_factory=list)
    via_function: bool = False
    sink_url_domain: str | None = None
    sink_is_external: bool | None = None
    sink_is_known_exfil_endpoint: bool = False
    known_endpoint: str | None = None
    truncated: bool = False  # the chain hit max_path_steps


class EvidenceItem(_Model):
    """One line of evidence behind a finding."""

    kind: Literal["flow_step", "source", "sink", "detection", "html", "script"]
    ref: int | None = None  # flow / source / sink id
    script_index: int | None = None
    line: int | None = None
    column: int | None = None
    code: str = ""
    note: str | None = None


class Finding(_Model):
    """A behavioral pattern found on the page (configs/behavior_patterns.yaml)."""

    pattern_id: str
    name: str
    variant: str
    severity: Severity
    severity_score: int  # 1 low ... 4 critical
    confidence: Confidence
    message: str  # plain English (Part 9 explanations)
    count: int = 1  # occurrences behind this finding
    script_index: int | None = None
    factors: list[str] = Field(default_factory=list)  # what raised / qualifies it
    flow_ids: list[int] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)  # ordered: numbered chain


class BehaviorMeta(_Model):
    schema_version: str = SCHEMA_VERSION
    sample_id: str | None = None
    dataset_version: str | None = None
    page_url: str | None = None
    base_url: str | None = None
    source_sha256: str | None = None
    js_rules_hash: str  # the Part 7 result this was built on
    rules_hash: str  # Part 8 rules (3 YAML files + field rules + analyzer version)
    processing_ms: float = 0.0
    step_ms: dict[str, float] = Field(default_factory=dict)
    truncated: bool = False  # a cap or time budget was hit (see warnings)
    warnings: list[str] = Field(default_factory=list)


class BehaviorSummary(_Model):
    scripts_analyzed: int = 0  # page-own scripts with an AST (taint analysis)
    scripts_lexical: int = 0  # page-own scripts with regex evidence only
    library_scripts_skipped: int = 0
    sources_total: int = 0
    sinks_total: int = 0
    flows_total: int = 0
    sources_by_id: dict[str, int] = Field(default_factory=dict)
    sinks_by_id: dict[str, int] = Field(default_factory=dict)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    max_severity: Severity | None = None
    passes: int = 0  # fixed-point passes of the taint analysis


class BehaviorResult(_Model):
    """Part 8 output for one page."""

    meta: BehaviorMeta
    feature_set_version: str
    summary: BehaviorSummary = Field(default_factory=BehaviorSummary)
    sources_found: list[SourceHit] = Field(default_factory=list)
    sinks_found: list[SinkHit] = Field(default_factory=list)
    flows: list[Flow] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)  # most severe first
    intent_vector: dict[str, float | int] = Field(default_factory=dict)  # behavior_features order
    behavior_risk_score: float = 0.0
    top_findings: list[str] = Field(default_factory=list)  # <= 5 lines for Part 9
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
